FROM ubuntu:20.04

LABEL version="1.0"
LABEL description="This is my Scripting workstation. Includes Ansible, PowerShell, PowerCLI."

# Run the package installs as Root
USER 0

# Update the OS, install Curl, PIP, PyVMOMI, VIM, and Ansible
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade && DEBIAN_FRONTEND=noninteractive apt-get \
    install -y software-properties-common curl python3-pip vim && pip install pyvmomi && add-apt-repository --yes \
    --update ppa:ansible/ansible && DEBIAN_FRONTEND=noninteractive apt-get install -y ansible 

# Install Microsoft Certs and PowerShell
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add && \
    curl -o /etc/apt/sources.list.d/microsoft.list https://packages.microsoft.com/config/ubuntu/20.04/prod.list && \
    apt-get update && apt-get install -y powershell

# Install VMware PowerCLI modules for PowerShell
RUN pwsh -Command "& {Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted}" && \
    pwsh -Command "& {Install-Module -Name VMware.PowerCLI}" -NonInteractive

# Expose the shared volumes for:
# - Scripts
# - Ansible Vaults
VOLUME ["/user/scripts", "/user/vault"]

# Create user-space
RUN mkdir /user && chown 1001.1001 /user 

# Transition to non-root user for primary shell
USER 1001

CMD ["bash"]
