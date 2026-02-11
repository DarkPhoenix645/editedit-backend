## Setup & Run Instructions

1. Create .env in the `infrastructure/` directory:

   ```
   # Password for the 'elastic' user (at least 6 characters)
   ELASTIC_PASSWORD=something

   # Password for the 'kibana_system' user (at least 6 characters)
   KIBANA_PASSWORD=something

   # Version of Elastic Stack to use
   STACK_VERSION=8.12.0

   # License to use (basic, trial, or platinum)
   LICENSE=basic

   # Ports to expose to the host
   ES_PORT=9200
   KIBANA_PORT=5601
   LOGSTASH_PORT=5044
   LOGSTASH_MONITORING_PORT=9600

   ENCRYPTION_KEY=<random 32-character string for Kibana encryption>
   ```

2. Run `docker compose up` from the `infrastructure/` directory.
3. Configure Fleet Server:
   1. In the Kibana UI, go to Management > Fleet > Agent Policies
   2. Create a new policy with the "Collect system logs and metrics" checkbox checked
   3. Create a new agent with "Add Agent" in Management > Fleet > Agents
   4. Copy the enrollment token
4. Configure Elastic Agent:
   1. Install [https://taskfile.dev/docs/installation](Task)
   2. From the root of the project, run `task host-agent:enroll <enrollment-token>`
