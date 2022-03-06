FROM ubuntu:impish

# Update sources and install git
RUN apt-get update -y && apt-get install -y git python3-pip

#Git configuration
RUN git config --global user.name "YOUR NAME HERE" \
    && git config --global user.email "YOUR EMAIL HERE"

# Clone SETOOLKIT
RUN git clone --depth=1 https://github.com/trustedsec/social-engineer-toolkit.git

# Change Working Directory
WORKDIR /social-engineer-toolkit

 # Install requirements
RUN pip3 install -r requirements.txt

# Install SETOOLKIT
RUN python3 setup.py 

ENTRYPOINT [ "./setoolkit" ]

    
