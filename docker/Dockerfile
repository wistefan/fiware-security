FROM python:3.7-alpine

LABEL com.jira-management.version="1.3.0" \
      vendor="FIWARE Foundation, e.V." \
      com.jira-management.release-date="2019-08-20" \
      com.jira-management.version.is-production="yes" \
      com.jira-management.maintainer="Fernando López <fernando.lopez@fiware.org>"

# Install dependencies
RUN apk update && \
    apk add --no-cache git && \
    pip install --no-cache-dir -Iv requests==2.22.0

# Define the default BRANCH to get the code
ARG BRANCH=master

# Create a group and user
RUN addgroup -S mgmt && adduser -S mgmt -G mgmt

# Define the working directory
WORKDIR /home/mgmt

# Get the python code of the service
RUN git clone -b $BRANCH https://github.com/flopezag/fiware-clair.git && \
    apk del git && \
    rm -f /var/cache/apk/* && \
    chown -R mgmt:mgmt fiware-clair/

# Tell docker that all future commands should run as the appuser user
USER mgmt

# Define the ENV variable
ENV CONFIG_FILE /home/mgmt/fiware-clair/Config/management.ini

# Execute the service
CMD [ "python", "/home/mgmt/fiware-clair/scan.py", "-s", "-d fiware/orion-ld"]