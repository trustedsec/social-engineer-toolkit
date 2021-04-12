FROM ubuntu:latest

# Update sources and install git
RUN apt update -y && apt install git -y && apt install python3-pip -y 

#Git configuration
RUN git config --global user.name "YOUR NAME HERE" \
    && git config --global user.email "YOUR EMAIL HERE"

# Clone SETOOLKIT
RUN git clone https://github.com/trustedsec/social-engineer-toolkit.git

# Change Working Directory
WORKDIR /social-engineer-toolkit

 # Install requirements
RUN pip3 install -r requirements.txt

# Install SETOOLKIT
RUN python3 setup.py 

ENTRYPOINT [ "./setoolkit" ]

    