# 🛡️ ShackledAgent

An AI-driven chat agent equipped with graph-based, real-time and stateful security validation and dynamic access control. The system enforces organizational policies using 

* **RDF** (Resource Description Framework)
* **SHACL** (Shapes Constraint Language)

graphs and integrates a Retrieval-Augmented Generation (RAG) pipeline with guardrails to monitor both incoming user intent and outgoing agent responses. 

At the core of the system is the enterprise network graph - referred to as the **ICA graph (Identity, Content and Attributes)** - which models all user roles, clearances, and document classification nodes.

---

## Built With

* **Frontend:** [Streamlit](https://streamlit.io/)
* **AI Engine:** [OpenAI API](https://github.com/openai/openai-python) (Deployed via Azure)
* **Semantic Web & Graphs:** [rdflib](https://rdflib.dev/) & [pyshacl](https://github.com/RDFLib/pySHACL)
* **Cloud Storage & Security:** Azure Blob Storage & Azure Identity
* **Graph Visualization:** Graphviz, [Graphviz Web Tool](https://dreampuf.github.io/GraphvizOnline/)

---

## Key Features

* **Dynamic Access Control (RAG Guardrails):** Validates user clearance levels (`Employee`, `Manager`, `Administrator`) against document classification blocks (`[CompanyRestricted]`, `[CompanyConfidential]`) dynamically parsed from the Knowledge Base via RDF graph lookups in the central ICA graph.
* **Dual-Layer Security System:** Scans prompt intent and generated output for unauthorized and malicious interactions using both targeted rule sets and synchronous LLM-based verification.
* **Compliance via SHACL Validation:** Automatically executes data compliance and warning routines using shapes and target constraints outlined in `shacl-rules.ttl`.
* **Hybrid Environment Support:** A simple configuration toggle allows the application to run entirely offline with local files or securely synchronized with Azure resources.
* **Graph Visualization & Admin Tools:** Built-in rendering engine enabling all users to view their current session state, alongside an exclusive Admin Panel for corporate network visualization and live text updates.

---

## Getting Started

### Prerequisites

Ensure you have Python installed (version 3.10+ recommended).

### 1. Installation

Clone this repository to your local machine and install the dependencies:

    git clone https://github.com/alicehagdahl/ShackledAgent.git
    cd shackled-agent
    pip install -r requirements.txt

---

## Environment Configuration

This project can be run in two different modes based on the `LOCAL` flag at the top of the main script. Choose the setup track that fits your environment.

### Track A: Local Development (`LOCAL = True`)

Use this mode to test and run the application entirely on your machine using local storage and text files.

#### 1. Configure the Source Code

Make sure the environment switch variable at the top of your script is set to `True`:

    # ENVIRONMENT SWITCH (Set to True for home testing, False for production cloud)
    LOCAL = True

#### 2. Set Up File Structure & Environment Variables

1. Create a folder named `local_files/` in the root directory of the project.
2. Create a file named `.env` inside the `API/` directory (`API/.env`) and add your credentials:

    ```env
    API_KEY=your_azure_openai_api_key
    
    AZURE_ENDPOINT=your_azure_endpoint
    ```

#### 3. Launch the App

Run the following command in your terminal:

    streamlit run app.py

> 💡 **Note:** The repository already includes pre-configured local data files located in `local_files/rag_local.md` and `local_files/ICA_graph_local.txt`. The application reads directly from these files when running locally. You are welcome to edit the content within `rag_local.md` to test different RAG responses, but it is critical that you only modify the text information and **do not alter the structural classification tags** (e.g., `[CompanyRestricted]` and `[CompanyConfidential]`).
---

### Track B: Cloud Production (`LOCAL = False`)

Use this mode when deploying the application to the cloud (e.g., Azure App Service) alongside cloud storage environments.

#### 1. Configure the Source Code

Change the environment switch variable at the top of your script to `False` before deploying your code:

    # ENVIRONMENT SWITCH (Set to True for home testing, False for production cloud)
    LOCAL = False

#### 2. Configure Azure Environment Variables

In your cloud deployment service settings (e.g., Azure App Service Configuration), add the following environment variables:

* `OPENAI_API_KEY`: Your Azure OpenAI API key.
* `AZURE_ENDPOINT`: Your Azure OpenAI endpoint URL.
* `STORAGE_ACCOUNT_NAME`: The name of your Azure Storage Account.

#### 3. Prepare Azure Blob Storage

1. Log in to your Azure Portal and create a blob storage container named `shackled-agent` in your storage account.
2. The application uses `DefaultAzureCredential()` to authenticate. Ensure that the environment hosting the application (e.g., your App Service's Managed Identity) has explicit **Storage Blob Data Contributor** permissions assigned to that container.
3. **Upload Required System Files:** You must manually upload two foundational files into your Azure blob container: `rag.md` and `ICA_graph.txt`. **Initially, these files must contain the exact same data and structure as `rag_local.md` and `ICA_graph_local.txt` respectively.**
   * *Note on editing:* Just like in the local setup, you can customize the knowledge base within `rag.md`, but you must **strictly preserve the internal document structure** and only modify the raw text information without changing or removing the structural classification tags.

---

## Usage & Testing

> ⚠️ **Important Notice:** The data, department structures, and employee profiles used in this application belong to a **fictional mock enterprise** created solely for demonstrating the system's security capabilities. The user IDs provided below are hardcoded into the initial knowledge graph and are the **only user IDs** that will successfully pass the login screen.

To test the application's graph-based access control and security features, you can log in using the pre-configured mock enterprise user IDs below. The login screen requires one of the specific user IDs listed below, all following the `uXXXX` pattern.

### Available Test Users

| User ID | Role | Department | Access Clearance |
| :--- | :--- | :--- | :--- |
| `u0000` | Administrator | IT-Security | CompanyConfidential, CompanyRestricted, Public, Admin Panel |
| `u2001` | Manager | Finance | CompanyConfidential, CompanyRestricted, Public |
| `u2002` | Manager | IT-Support | CompanyConfidential, CompanyRestricted, Public |
| `u1001` | Employee | Finance | CompanyRestricted, Public |
| `u1002` | Employee | IT-Support | CompanyRestricted, Public |
| `u1003` | Employee | HR | CompanyRestricted, Public |

### How to Test the Guardrails
1. **Role-Based Access Control:** Log in as an Employee (`u1001`) and ask the agent about confidential company data. The agent's output guardrail will dynamically deny access based on the RDF graph state. Log in as a Manager (`u2001`) to see the confidential content successfully rendered.
2. **Real-time SHACL Audits:** Try logging out after asking malicious or suspicious questions. The AI will evaluate the session history, update the graph, and execute SHACL compliance validation rules in `shacl-rules.ttl` to automatically assign warning flags (Yellow/Red) to your user profile.
3. **Graph Visualizations:** While logged in, any user can expand the visualization UI component to view their current local **RDF session graph** generated via Graphviz. This maps their specific queries, timestamps, and active compliance flags in real time.
4. **Admin Controls:** Log in as the Administrator (`u0000`) to unlock the exclusive **Admin Control Panel** in the sidebar. This elevated view allows you to visualize the full global **ICA graph** representing the entire enterprise network structure. Administrators can also edit corporate data on the fly or reset the enterprise database back to its original bootstrap state directly from this panel; however, it is critical to ensure that only the information is modified and the correct Turtle syntax is strictly preserved.

---

## Security Architecture & SHACL Validation

The application utilizes **SHACL (Shapes Constraint Language)** via the `pyshacl` engine to enforce real-time security compliance and automated user governance. Instead of hardcoding security logic in Python, corporate rules are completely decoupled into `shacl-rules.ttl` and divided into two operational layers: **Session Rules** and **Permanent Governance Rules**.

### 1. Real-Time Session Rules
These shapes are evaluated instantly during a chat session to validate ongoing queries and enforce strict data boundaries:

* **Rule 1a (`ex:MaliciousCheckShape`): Single Query Block** Monitors incoming user prompts. If an input query is flagged by the security pipeline as `Malicious`, this constraint immediately blocks the transaction and prevents the query from being processed further.
* **Rule 2a (`ex:WholeChatBlockedShape`): Session Abuse Threshold** A SPARQL-based constraint that aggregates historical queries within the current session. If a user accumulates **3 or more malicious queries** inside a single chat thread, the rule triggers a critical system halt.
* **Rule 3a (`ex:SafetyNetShape`): RAG Context Leak Prevention** Acts as a structural semantic firewall. This SPARQL constraint looks up the active user's role inside the knowledge graph. If the current query targets data marked as `CompanyConfidential` and the user's assigned role lacks explicit clearance, access is instantly denied.
* **Rule 4a (`ex:OutputGuardrailShape`): Agent Output Defense** Evaluates the agent's completed response before it renders on the Streamlit screen. If the output generation triggers a `Malicious` safety flag (e.g., leaking corporate data or violating content restrictions), this rule overrides the response with a secure fallback warning.

### 2. Long-Term Permanent Rules
These advanced inference rules (`sh:rule`) run asynchronously when a user logs out, applying persistent behavioral tracking directly to their database profiles (excluding the administrator `u0000`):

* **Rule 1b (`ex:WarningBlockRuleShape`): Automated Account Warning** A SPARQL rule that audits the persistent database for security incidents. If a user accumulates **1 to 2 malicious sessions**, the system infers a policy violation, attaches a permanent `ex:globalSecurityStatus "Yellow"` warning flag to their node, and triggers a warning message within the application.
* **Rule 2b (`ex:PermanentBlockRuleShape`): Automated Account Suspension** Acts as the system's ultimate compliance mechanism. If a user reaches a threshold of **3 or more malicious sessions**, this SPARQL rule escalates their profile to a permanent `globalSecurityStatus: "Red"` flag, which completely revokes all future authentication privileges.
