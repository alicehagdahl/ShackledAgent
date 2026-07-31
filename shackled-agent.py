# =====================================================================
# SYSTEM CONFIGURATION & IMPORTS
# =====================================================================

import os
import re
import time
import requests

from rdflib import Graph, URIRef, Literal, Namespace, XSD
from rdflib.namespace import RDF
from pyshacl import validate
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

st.set_page_config(page_title="ShackledAgent", page_icon="🛡️")

# ENVIRONMENT SWITCH (Set to True for home testing, False for production cloud)
LOCAL = True

if LOCAL:
    DOCUMENT_FILE = "local_files/rag_local.md"
    GRAPH_FILE = "local_files/ICA_graph_local.txt"
    # Fetches from the local .env file
    load_dotenv("API/.env")
    AZURE_API_KEY = os.getenv("API_KEY")
    AZURE_ENDPOINT = os.getenv("AZURE_ENDPOINT")
else:
    # In production (Azure), these are fetched from the app's environment variables
    AZURE_API_KEY = os.environ.get("OPENAI_API_KEY")
    AZURE_ENDPOINT = os.environ.get("AZURE_ENDPOINT")
    STORAGE_ACCOUNT_NAME = os.environ.get("STORAGE_ACCOUNT_NAME")
    CONTAINER_NAME = "shackled-agent"
    DOCUMENT_FILE = "rag.md"
    GRAPH_FILE = "ICA_graph.txt"

# Shared parameters that remain unchanged
AZURE_API_VERSION = "2024-06-01"
MODEL_DEPLOYMENT_NAME = "gpt-4o"
EX = Namespace("http://example.org/")

# Initialize the client after the endpoint has been retrieved
client = OpenAI(base_url=AZURE_ENDPOINT, api_key=AZURE_API_KEY)

# =====================================================================
# CORE FUNCTIONS (Security & AI logic)
# =====================================================================

# Automatic IP-based Geolocation lookup helper
def get_visitor_location():
    try:
        response = requests.get("https://ipapi.co/json/", timeout=3)
        if response.status_code == 200:
            data = response.json()
            city = data.get("city", "Unknown City")
            country = data.get("country_name", "Unknown Country")
            return f"{city}, {country}"
    except Exception:
        pass
    return "Unknown location"

# Fetch or create the ICA (Identity, Context & Attributes) RDF graph - Supports both local file and Azure Blob Storage
def load_or_create_graph():
    g = Graph()
    g.bind("ex", EX)
    g.bind("rdf", RDF)
    
    # CHECK 1: Running in local environment?
    if LOCAL and os.path.exists(GRAPH_FILE):
        try:
            g.parse(GRAPH_FILE, format="turtle")
            return g
        except Exception as e:
            st.sidebar.error(f"Error reading local graph file: {e}")
            return g

    # CHECK 2: Production environment - Connect to Azure Blob Storage
    try:
        credential = DefaultAzureCredential()
        account_url = f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net"
        blob_service_client = BlobServiceClient(account_url, credential=credential)
        blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=GRAPH_FILE)
        
        blob_data = blob_client.download_blob().readall()
        g.parse(data=blob_data, format="turtle")
        return g
    except Exception:
        # CHECK 3: If no file exists anywhere, bootstrap the base graph structure in memory
        employees = [
            {"id": "u0000", "role": "Administrator", "department": "IT-Security"},
            {"id": "u1001", "role": "Employee", "department": "Finance"},
            {"id": "u1002", "role": "Employee", "department": "IT-Support"},
            {"id": "u1003", "role": "Employee", "department": "HR"},
            {"id": "u2001", "role": "Manager", "department": "Finance"},
            {"id": "u2002", "role": "Manager", "department": "IT-Support"}
        ]
        for person in employees:
            person_ref = EX[person["id"]]
            g.add((person_ref, RDF.type, EX.Employee))
            # Links the role dynamically as an RDF resource (URI) instead of a Literal string
            g.add((person_ref, EX.hasRole, EX[person["role"]]))
            g.add((person_ref, EX.belongsToDepartment, Literal(person["department"])))

            if person["id"] == "u0000":
                g.add((person_ref, RDF.type, EX.Admin))
        
        # Bootstrap default access policies in the Graph structure
        g.add((EX.Administrator, EX.hasAccessToLevel, EX.CompanyConfidential))
        g.add((EX.Administrator, EX.hasAccessToLevel, EX.CompanyRestricted))

        g.add((EX.Manager, EX.hasAccessToLevel, EX.CompanyConfidential))
        g.add((EX.Manager, EX.hasAccessToLevel, EX.CompanyRestricted))

        g.add((EX.Employee, EX.hasAccessToLevel, EX.CompanyRestricted))
        
        # Serialize and save the bootstrapped base structure (Local or Azure)
        turtle_data = g.serialize(format="turtle")
        if LOCAL:
            with open(GRAPH_FILE, "w", encoding="utf-8") as f:
                f.write(turtle_data)
        else:
            try:
                blob_client.upload_blob(turtle_data, overwrite=True)
            except Exception as e:
                st.sidebar.error(f"Could not initialize Azure blob: {str(e)}")
                
        return g

# Saves session data permanently and evaluates compliance rules - Supports both local file and Azure
def save_session_permanently(user, history, temporary_graph):
    try:
        ICA_graph = load_or_create_graph()
        session_id = st.session_state.get("current_session_id", f"Session_{int(time.time())}")
        session_ref = EX[session_id]
        user_ref = EX[user]
        
        # Retrieve the user's simulated location from session state
        user_location = st.session_state.get("location", "Unknown Location")
        
        if history:
            overall_topic = generate_session_topic_with_ai(history)
        else:
            overall_topic = "No conversation"
        
        # --- LOGIC TO FETCH SECURITY STATUS ---
        security_status = "Green"
        
        # 1. Check if the prompt has been flagged as Malicious (temporary_graph is the temporary session graph)
        for s, p, o in temporary_graph.triples((None, EX.securityStatus, None)):
            if str(o) in ["Malicious"]:
                security_status = str(o)
                break
                
        # 2. ALSO check if the agent's response has been flagged as Malicious (if the prompt was Green)
        if security_status != "Malicious":
            for s, p, o in temporary_graph.triples((None, EX.outputSecurityStatus, None)):
                if str(o) in ["Malicious"]:
                    security_status = str(o)
                    break
        # -----------------------------------------------------
                
        ICA_graph.add((session_ref, RDF.type, EX.ChatSession))
        ICA_graph.add((session_ref, EX.startedBy, user_ref))
        ICA_graph.add((session_ref, EX.topic, Literal(overall_topic)))
        ICA_graph.add((session_ref, EX.sessionStatus, Literal(security_status)))
        
        # Saves timestamp according to ISO standards with semantic typing (xsd:dateTime)
        current_timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        ICA_graph.add((session_ref, EX.date, Literal(current_timestamp, datatype=XSD.dateTime)))
        
        # Add the physical/logical login location to the graph
        ICA_graph.add((session_ref, EX.location, Literal(user_location)))
        
        ICA_graph.bind("ex", EX)
        ICA_graph.bind("rdf", RDF)

        # Clear the user's old flag before SHACL recalculates the status
        ICA_graph.remove((user_ref, EX.globalSecurityStatus, None))

        shacl_graph = Graph()
        shacl_graph.parse("shacl-rules.ttl", format="turtle")

        # Run SHACL validation (advanced rules/SPARQL rules are executed in-place in memory)
        validate(
            data_graph=ICA_graph,
            shacl_graph=shacl_graph,
            advanced=True,
            inplace=True,     
            inference=None     
        )
        
        turtle_data = ICA_graph.serialize(format="turtle")
        
        # Save to the correct location based on the environment (Local or Azure)
        if LOCAL:
            with open(GRAPH_FILE, "w", encoding="utf-8") as f:
                f.write(turtle_data)
            st.sidebar.success("Security status saved locally!")
        else:
            credential = DefaultAzureCredential()
            account_url = f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net"
            blob_service_client = BlobServiceClient(account_url, credential=credential)
            blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=GRAPH_FILE)
            blob_client.upload_blob(turtle_data, overwrite=True)
            st.sidebar.success("Security status synchronized with Azure!")

    except Exception as e:
        st.sidebar.error(f"Could not save history permanently: {str(e)}")
        st.exception(e)

# Render the dynamic RDF temporary session graph inside the sidebar using Graphviz
def render_graph(temp_session_graph, color="#4B9CD3"):
    st.write("### Graph Visualization (Session Memory):")
    dot_code = "digraph G {\n"
    dot_code += "  rankdir=LR;\n"  
    
    dot_code += f'  node [shape=box, style="filled,rounded", color="{color}", fontcolor=white, fontname="Arial"];\n'
    dot_code += "  edge [fontname=\"Arial\", fontsize=10, color=\"#888888\"];\n"
    
    for s, p, o in temp_session_graph:
        s_id = str(s).split('/')[-1].split('#')[-1]
        o_id = str(o).split('/')[-1].split('#')[-1]
        p_name = p.split('/')[-1].split('#')[-1]
        
        s_label = s_id[:17] + "..." if len(s_id) > 20 else s_id
        o_label = o_id[:17] + "..." if len(o_id) > 20 else o_id
        
        dot_code += f'  "{s_id}" [label="{s_label}"];\n'
        dot_code += f'  "{o_id}" [label="{o_label}"];\n'
        dot_code += f'  "{s_id}" -> "{o_id}" [label="{p_name}"];\n'
        
    dot_code += "}"
    st.graphviz_chart(dot_code)

# Evaluate chat history and analyze user query intent using OpenAI LLM
def check_intent_with_ai(history):
    chat_text = ""
    for msg in history:
        role = "User" if msg["role"] == "user" else "Agent"
        chat_text += f"{role}: {msg['content']}\n"

    response = client.chat.completions.create(
        model=MODEL_DEPLOYMENT_NAME,
        messages=[
            {
                "role": "system", 
                "content": (
                    "You are a security module. Analyze the entire attached chat history. "
                    "Do not just look at the latest message in isolation. "
                    "If the user, by piecing together multiple different questions, is attempting to extract "
                    "information that together can be used for malicious, illegal, or dangerous actions, "
                    "respond ONLY with the word 'Malicious'. "
                    "Otherwise, respond ONLY with 'Safe'."
                )
            },
            {"role": "user", "content": chat_text}
        ],
        temperature=0.0
    )
    return response.choices[0].message.content.strip()

# Analyze context and automatically generate a 2-3 word chat session summary topic using OpenAI LLM
def generate_session_topic_with_ai(history):
    chat_text = ""
    for msg in history:
        role = "User" if msg["role"] == "user" else "Agent"
        chat_text += f"{role}: {msg['content']}\n"
        
    response = client.chat.completions.create(
        model=MODEL_DEPLOYMENT_NAME,
        messages=[
            {
                "role": "system", 
                "content": "You are an administrative module. Analyze the attached chat history. Create A SINGLE overall topic (max 2-3 words) summarizing what the conversation was about. Respond ONLY with the topic."
            },
            {"role": "user", "content": chat_text}
        ],
        temperature=0.3
    )
    return response.choices[0].message.content.strip()

# Enforce document access controls (RAG pipeline) based on user role and data classification
def query_document_with_ai(user_text):
    full_content = ""
    
    # 1. Load document (Local or Azure)
    if LOCAL and os.path.exists(DOCUMENT_FILE):
        with open(DOCUMENT_FILE, "r", encoding="utf-8") as f:
            full_content = f.read()
    else:
        try:
            credential = DefaultAzureCredential()
            account_url = f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net"
            blob_service_client = BlobServiceClient(account_url, credential=credential)
            blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=DOCUMENT_FILE)
            full_content = blob_client.download_blob().readall().decode('utf-8')
        except Exception as e:
            full_content = f"# Error connecting securely to Azure Storage: {str(e)}"

    user_role = st.session_state.get("role", "Employee")

    # Locate where the safety and confidential sections start in the document
    find_restricted_section = re.search(r"\[CompanyRestricted\]", full_content)
    find_secret_section = re.search(r"\[CompanyConfidential\]", full_content)

    # ─── DYNAMIC ACCESS CONTROL QUERYING THE RDF GRAPH ─────────────────────
    ICA_graph = load_or_create_graph()
    
    # Build URI resource references for the user role and policy levels
    role_uri = EX[user_role]                      # e.g., ex:Manager, ex:Employee or ex:Administrator
    restricted_level = EX.CompanyRestricted       # ex:CompanyRestricted
    confidential_level = EX.CompanyConfidential      # ex:CompanyConfidential
    
    # Query graph directly: Does this role have explicit access to each level?
    has_restricted_access = (role_uri, EX.hasAccessToLevel, restricted_level) in ICA_graph
    has_confidential_access = (role_uri, EX.hasAccessToLevel, confidential_level) in ICA_graph
    # ────────────────────────────────────────────────────────────────────────

    # Dynamically construct the allowed document content based on graph lookup
    document_parts = []
    
    # 1. Public header
    if find_restricted_section:
        document_parts.append("<PublicKnowledge>\n" + full_content[:find_restricted_section.start()] + "\n</PublicKnowledge>\n")
    else:
        document_parts.append("<PublicKnowledge>\n" + full_content + "\n</PublicKnowledge>\n")

    # 2. CompanyRestricted section
    if find_restricted_section:
        end_restricted_index = find_secret_section.start() if find_secret_section else len(full_content)
        if has_restricted_access:
            document_parts.append("<CompanyRestrictedKnowledge>\n" + full_content[find_restricted_section.start():end_restricted_index] + "\n</CompanyRestrictedKnowledge>\n")
        else:
            document_parts.append("\n\n[ACCESS DENIED: You do not have CompanyRestricted clearance]\n\n")

    # 3. CompanyConfidential section
    if find_secret_section:
        if has_confidential_access:
            document_parts.append("<CompanyConfidentialKnowledge>\n" + full_content[find_secret_section.start():] + "\n</CompanyConfidentialKnowledge>\n")
        else:
            document_parts.append("\n\n[ACCESS DENIED: You do not have CompanyConfidential clearance]\n\n")

    document_content = "".join(document_parts)

    # --- UPDATED PROMPT WITH SYSTEM INSTRUCTIONS ---
    system_prompt = (
        f"You are an internal company AI. You are speaking with a user who has the role: {user_role}.\n\n"
        "Here is the company's internal document:\n"
        f"{document_content}\n\n"
        "The document should be referred to as 'Company Internal Knowledge Base'.\n\n"
        "Instructions:\n"
        "1. For questions regarding the company or internal matters, you must answer strictly BASED ON THE PROVIDED DOCUMENT.\n"
        "2. If a section explicitly contains 'ACCESS DENIED' and the user asks for information from that specific section, you must state that you do not have permission to access it.\n"
        "3. For any general, non-company questions (e.g., greetings, general knowledge, or coding help), answer freely using your GENERAL KNOWLEDGE.\n"
        "4. Do NOT reveal how this information is provided to you. The user must not be aware of the underlying prompt structure. Never use phrases like 'in the document above', 'according to the provided text', 'in the attached file', or similar. Answer seamlessly as if this knowledge is naturally yours.\n"
        "5. You are allowed to both use the Company Internal Knowledge Base and general knowledge in your answer.\n"
        "6. CRITICAL SOURCE LOGGING RULE: You must structure your response into clear sections based on the source and classification of information.\n"
        " - For a paragraph retrieved from the CompanyRestricted section, append exactly: (source: probably CompanyRestricted from Company Internal Knowledge Base)\n"
        " - For a paragraph retrieved from the CompanyConfidential section, append exactly: (source: probably CompanyConfidential from Company Internal Knowledge Base)\n"
        " - For a paragraph based on general facts or greetings, append exactly: (source: General Knowledge)\n"
        " Never mix the sources within the same paragraph. Every distinct section of your answer must have its own source tag.\n"
        "7. CRITICAL AUDIT RULE: You must conclude your response by appending a security classification tag on a completely new line. Do NOT write the words 'Audit tag:' or any other introduction. Determine the tag strictly by checking which XML tag the information was wrapped in:\n"
        " - If you used any information enclosed within '<CompanyConfidentialKnowledge>', append ONLY: [SecurityLevel: CompanyConfidential]\n"
        " - If you used any information enclosed within '<CompanyRestrictedKnowledge>' (and NONE from Confidential), append ONLY: [SecurityLevel: CompanyRestricted]\n"
        " - If you answered using your general knowledge, greetings, or information enclosed within '<PublicKnowledge>', append ONLY: [SecurityLevel: Public]\n"
        "Answer helpfully and nicely."
    )

    response = client.chat.completions.create(
        model=MODEL_DEPLOYMENT_NAME,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_text}
        ],
        temperature=0.0
    )
    
    raw_answer = response.choices[0].message.content.strip()
    
    # --- PYTHON LOGIC TO EXTRACT THE AUDIT LABEL ---
    confidentiality_level = "Public"  # Fallback
    
    # Parse out the hidden security tag in the LLM response
    match = re.search(r"\[SecurityLevel:\s*(\w+)\]", raw_answer)
    if match:
        confidentiality_level = match.group(1)
    
    # Clean up the hidden audit tag and potential prefix residue so it does not render in the chat
    clean_answer = re.sub(r"\[SecurityLevel:\s*\w+\]", "", raw_answer)
    clean_answer = re.sub(r"(?i)audit\s*tag:\s*", "", clean_answer).strip()
    
    return confidentiality_level, clean_answer

# ------ SECURITY SYSTEM ------

# Central entry point for processing and validating real-time input/output compliance graph rules
def run_security_system(user, query_text):
    temporary_session_graph = st.session_state.g 
    unique_timestamp = int(time.time() * 1000000)
    query_id = abs(hash(query_text)) + unique_timestamp
    user_ref = EX[user]
    query_ref = EX[f"Query_{query_id}"]
    
    session_id = st.session_state.get("current_session_id", f"Session_{int(time.time())}")
    session_ref = EX[session_id]

    # 1. Build basic session graph for the prompt
    temporary_session_graph.add((query_ref, EX.textContent, Literal(query_text)))
    temporary_session_graph.add((query_ref, RDF.type, EX.Query))
    temporary_session_graph.add((session_ref, EX.containsQuery, query_ref)) 
    temporary_session_graph.add((session_ref, RDF.type, EX.ChatSession))
    temporary_session_graph.add((session_ref, EX.startedBy, user_ref))
    temporary_session_graph.remove((user_ref, EX.hasRole, None))
    # Links dynamic URI resource mapping for real-time validation compliance
    temporary_session_graph.add((user_ref, EX.hasRole, EX[st.session_state.role]))

    # 2. Assign security status for the PROMPT (Forbidden words or AI intent check)
    forbidden_words = ["bomb", "thief", "cheat"]
    if any(word_ in query_text.lower() for word_ in forbidden_words):
        temporary_session_graph.add((query_ref, EX.securityStatus, Literal("Malicious")))
    else:
        history = st.session_state.get("messages", []) + [{"role": "user", "content": query_text}]
        intent = check_intent_with_ai(history)
        temporary_session_graph.add((query_ref, EX.securityStatus, Literal(intent.capitalize())))

    # 3. Fetch OpenAI response and tag data classification section
    confidentiality_level, document_response = query_document_with_ai(query_text)
    
    if confidentiality_level == "CompanyConfidential":
        temporary_session_graph.add((query_ref, EX.concernsConfLevel, EX.CompanyConfidential))
    elif confidentiality_level == "CompanyRestricted":
        temporary_session_graph.add((query_ref, EX.concernsConfLevel, EX.CompanyRestricted))
    else:
        temporary_session_graph.add((query_ref, EX.concernsConfLevel, EX.Public))

    # 4. Output guardrail (Enforces Dynamic Graph-Based Access Control on Agent Output)
    user_role = st.session_state.get("role", "Employee")
    
    # Hämtar grafen och kollar rollens faktiska accessnoder live
    ICA_graph = load_or_create_graph()
    role_uri = EX[user_role]
    has_restricted_access = (role_uri, EX.hasAccessToLevel, EX.CompanyRestricted) in ICA_graph
    has_confidential_access = (role_uri, EX.hasAccessToLevel, EX.CompanyConfidential) in ICA_graph

    # --- DYNAMIC GRAPH CHECK ---
    is_unauthorized_confidential = (confidentiality_level == "CompanyConfidential" and not has_confidential_access)
    is_unauthorized_restricted = (confidentiality_level == "CompanyRestricted" and not has_restricted_access)

    if is_unauthorized_confidential or is_unauthorized_restricted:
        temporary_session_graph.add((query_ref, EX.outputSecurityStatus, Literal("Malicious")))
    else:
        if any(word_ in document_response.lower() for word_ in forbidden_words):
            temporary_session_graph.add((query_ref, EX.outputSecurityStatus, Literal("Malicious")))
        else:
            output_history = st.session_state.get("messages", []) + [
                {"role": "user", "content": query_text},
                {"role": "assistant", "content": document_response}
            ]
            output_intent = check_intent_with_ai(output_history)
            temporary_session_graph.add((query_ref, EX.outputSecurityStatus, Literal(output_intent.capitalize())))

    # 5. RUN A SINGLE SHACL VALIDATION FOR ALL ENGINE RULES
    try:
        temporary_session_graph.bind("ex", EX)
        temporary_session_graph.bind("rdf", RDF)

        # Combine graphs
        validation_graph = temporary_session_graph + ICA_graph
        
        validation_graph.bind("ex", EX)
        validation_graph.bind("rdf", RDF)
        
        # Läser in filen direkt här istället för via hjälpfunktion
        shacl_graf = Graph()
        shacl_graf.bind("ex", EX)
        shacl_graf.parse("shacl-rules.ttl", format="turtle")

        conforms, v_graph, _ = validate(
            data_graph=validation_graph, 
            shacl_graph=shacl_graf,
            inference=None
        )
        
        st.sidebar.text(f"SHACL Conforms: {conforms}")
        
        if not conforms:
            SH = Namespace("http://www.w3.org/ns/shacl#")
            error_messages = []
            for s, p, o in v_graph.triples((None, SH.resultMessage, None)):
                error_messages.append(str(o))
            
            unique_errors = sorted(list(set(error_messages)))
            exact_error_message = "\n\n".join(unique_errors)
            
            return False, exact_error_message

        return True, document_response

    except Exception as e:
        return False, f"System error during security validation: {str(e)}"

# =====================================================================
# STREAMLIT USER INTERFACE (UI)
# =====================================================================

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "role" not in st.session_state:
    st.session_state.role = ""
if "department" not in st.session_state:
    st.session_state.department = ""
if "current_session_id" not in st.session_state:
    st.session_state.current_session_id = ""
if "previously_selected_file" not in st.session_state:
    st.session_state.previously_selected_file = ""
if "location" not in st.session_state:
    st.session_state.location = ""

if "g" not in st.session_state:
    st.session_state.g = Graph()
    st.session_state.g.bind("ex", EX)

# --- SCREEN 1: LOGIN WINDOW ---
if not st.session_state.logged_in:

    st.title("🛡️ Access Required")
    st.write("Please enter your username to proceed to the secure AI Agent.")
    
    # Wrap login inputs inside a form to enable submission via the 'Enter' key
    with st.form("login_form", clear_on_submit=False):
        username_input = st.text_input("Username (e.g., u1001 or u2001):", placeholder="u1234")
        submit_button = st.form_submit_button("Log In")
        
    # Process login parameters upon form submission
    if submit_button:
        if re.match(r"^u\d{4}$", username_input):
            permanent_g = load_or_create_graph()
            user_ref = EX[username_input]
            
            if (user_ref, None, None) in permanent_g:
                
                # Check for permanent suspension (Red flag)
                is_permanently_blocked = False
                for s, p, o in permanent_g.triples((user_ref, EX.globalSecurityStatus, None)):
                    if str(o) == "Red":
                        is_permanently_blocked = True

                # Halt execution if the user is permanently blocked
                if is_permanently_blocked:
                    st.error("🚨 ACCESS DENIED: This account has been permanently suspended due to repeated security policy violations.")
                    st.stop()
                
                # Initialize session state variables for successful login
                st.session_state.username = username_input
                st.session_state.logged_in = True
                st.session_state.current_session_id = f"Session_{int(time.time())}"
                st.session_state.messages = [] 
                
                # Automatically detect physical/logical location on login
                st.session_state.location = get_visitor_location()
                
                # Check for account warning status (Yellow flag)
                has_yellow_warning = False
                for s, p, o in permanent_g.triples((user_ref, EX.globalSecurityStatus, None)):
                    if str(o) == "Yellow":
                        has_yellow_warning = True

                # Inject a system alert message into the chat history if flagged with a warning
                if has_yellow_warning:
                    warning_message = (
                        "⚠️ ATTENTION! Your account has been flagged with a *Yellow warning* "
                        "due to previous queries violating our safety guidelines. "
                        "Further violations will result in permanent account suspension."
                    )
                    st.session_state.messages.append({"role": "assistant", "content": warning_message})
                
                # Retrieve the employee's designated role and department from the permanent graph
                role_value = ""
                department_value = ""
                for s, p, o in permanent_g.triples((user_ref, EX.hasRole, None)):
                    # Cleans URI namespace if stored as resource reference
                    role_value = str(o).split('/')[-1].split('#')[-1]
                for s, p, o in permanent_g.triples((user_ref, EX.belongsToDepartment, None)):
                    department_value = str(o)
                
                st.session_state.role = role_value.strip()
                st.session_state.department = department_value
                
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Access denied! Username is not registered in the database.")
        else:
            st.error("Invalid format! Must be a lowercase 'u' followed by exactly 4 digits.")
            
    st.stop()

# --- SCREEN 2: CHAT INTERFACE (LOGGED IN) ---
st.title("🤖 My Shackled AI Agent")
st.write(f"Logged in as: **{st.session_state.username}** ({st.session_state.role})")

st.sidebar.header("⚙️ Profile")
st.sidebar.write(f"User: `{st.session_state.username}`")
st.sidebar.write(f"Role: `{st.session_state.role}`")
st.sidebar.write(f"Location: `{st.session_state.location}`")
st.sidebar.write(f"Session: `{st.session_state.current_session_id}`")

if st.sidebar.button("Log Out / Reset"):
    if len(st.session_state.g) > 0 and st.session_state.username:
        with st.spinner("AI is summarizing the session and evaluating compliance rules..."):
            save_session_permanently(
                st.session_state.username, 
                st.session_state.messages, 
                st.session_state.g
            )
    
    st.session_state.clear()
    
    st.session_state.messages = []
    st.session_state.g = Graph()
    st.session_state.g.bind("ex", EX)
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.session_state.department = ""
    st.session_state.current_session_id = ""
    st.session_state.previously_selected_file = ""
    st.session_state.location = ""
    st.rerun()

if "messages" not in st.session_state:
    st.session_state.messages = []

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

if prompt := st.chat_input("Ask the agent a question..."):
    with st.chat_message("user"):
        st.markdown(prompt)
    
    st.session_state.messages.append({"role": "user", "content": prompt})

    # Clear administrator view cache on new prompt to ensure real-time rendering
    if "admin_text_content" in st.session_state:
        del st.session_state["admin_text_content"]
    
    with st.spinner("Security check in progress..."):
        approved, response_content = run_security_system(st.session_state.username, prompt)

    with st.chat_message("assistant"):
        if not approved:
            st.error(response_content)
        else:
            st.markdown(response_content) 
            st.session_state.messages.append({"role": "assistant", "content": response_content})

if len(st.session_state.g) > 0:
    with st.sidebar.expander("📊 View Knowledge Graph (RDF)"):
        render_graph(st.session_state.g)

# --- ADMINISTRATOR PANEL (Equipped with a horizontal pills banner) ---
ADMIN_ID = "u0000" 

if st.session_state.get("logged_in") and st.session_state.get("username") == ADMIN_ID:
    st.sidebar.markdown("---")
    
    # Interactive visualization of the permanent ICA hierarchy graph
    with st.sidebar.expander("🌐 View ICA Graph (RDF)"):
        with st.spinner("Loading database graph..."):
            try:
                # Loads the saved organization database directly from local or Azure storage
                ica_permanent_graph = load_or_create_graph()
                if len(ica_permanent_graph) > 0:
                    render_graph(ica_permanent_graph, color="#2E7D32")
                else:
                    st.warning("Permanent graph is empty.")
            except Exception as e:
                st.error(f"Could not render ICA graph: {e}")

    with st.sidebar.expander("🛠️ Admin Control Panel", expanded=True):
        st.subheader("Edit System Files")
        
        # UI label mapping using dynamic file variables
        file_mapping = {
            "🌐 ICA Graph (Turtle)": GRAPH_FILE,
            "📝 Company Internal Knowledge Base.md": DOCUMENT_FILE
        }
        
        # Horizontal tab layout selector
        selected_display_name = st.pills(
            label="Select file to edit:", 
            options=list(file_mapping.keys()), 
            default=list(file_mapping.keys())[0]
        )

        if selected_display_name is None:
            selected_display_name = list(file_mapping.keys())[0]
        
        actual_file = file_mapping[selected_display_name]
        
        # Clear buffer cache immediately upon switching nodes
        if st.session_state.get("previously_selected_file") != selected_display_name:
            st.session_state["previously_selected_file"] = selected_display_name
            if "admin_text_content" in st.session_state:
                del st.session_state["admin_text_content"]

        # Fetch active content from source pipeline
        if "admin_text_content" not in st.session_state:
            with st.spinner("Fetching system file..."):
                try:
                    if LOCAL:
                        with open(actual_file, "r", encoding="utf-8") as f:
                            st.session_state["admin_text_content"] = f.read()
                    else:
                        credential = DefaultAzureCredential()
                        account_url = f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net"
                        blob_service_client = BlobServiceClient(account_url, credential=credential)
                        blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=actual_file)
                        st.session_state["admin_text_content"] = blob_client.download_blob().readall().decode('utf-8')
                except Exception as e:
                    st.session_state["admin_text_content"] = ""
                    st.error(f"Could not load data element: {e}")

        st.markdown("---")
        st.caption(f"Active Target: `{actual_file}`")

        # Code editor field block
        new_text = st.text_area(
            label="Edit Content:",
            value=st.session_state.get("admin_text_content", ""),
            height=300,
            key=f"edit_{selected_display_name}"
        )
        
        # Commit action button
        if st.button("💾 Save Changes", use_container_width=True):
            try:
                with st.spinner("Committing changes to storage node..."):
                    if LOCAL:
                        with open(actual_file, "w", encoding="utf-8") as f:
                            f.write(new_text)
                        st.success("✓ File successfully saved locally!")
                    else:
                        credential = DefaultAzureCredential()
                        account_url = f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net"
                        blob_service_client = BlobServiceClient(account_url, credential=credential)
                        blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=actual_file)
                        blob_client.upload_blob(new_text, overwrite=True)
                        st.success("✓ Database updated live in Azure Storage!")
                    
                    st.session_state["admin_text_content"] = new_text
                    time.sleep(0.5)
                    st.rerun()
            except Exception as e:
                st.error(f"Commit failed: {e}")