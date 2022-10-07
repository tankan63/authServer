from python:3 

run apt-get update
#run apt install python3-pip
run pip install --no-cache-dir --upgrade pip
run pip install toml
run pip install passlib
run pip install coloredlogs
run pip install argon2-cffi
run pip install -v protobuf==3.20.*
run apt install protobuf-compiler -y

copy /src/ /app/

#run chmod +x /app/solution.py

entrypoint ["python3", "/app/service.py"]  
