# Service Server (Group 4)

Port: 8003

python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8003

See docs/team/group-4-services-security.md for more info.
