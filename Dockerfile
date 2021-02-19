FROM python:3.8-slim

# Update sources
RUN apt update -y

# Install git 
RUN apt install -y git

# Clone SETOOLKIT
RUN git clone https://github.com/trustedsec/social-engineer-toolkit.git

# Change Working Directory
WORKDIR social-engineer-toolkit

# Install requirements
RUN pip3 install -r requirements.txt

# Install SETOOLKIT
RUN python setup.py

    