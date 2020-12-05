# Base image
FROM ubuntu:18.04

# Labels and Credits
LABEL \
    name="Rickon" \
    author="Siva krishna" \
    description="Rickon tool"

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
RUN apt update
RUN apt-get install -y git \
    parallel python3 python3-pip

# Download and install go 1.13
COPY --from=golang:1.14 /usr/local/go/ /usr/local/go/

# Environment vars
ENV DATABASE="postgres"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"
ENV PATH="${PATH}:${GOROOT}/bin"
ENV PATH="${PATH}:${GOPATH}/bin"

# Download Go packages
RUN go get -u -v github.com/hakluke/hakrawler github.com/ffuf/ffuf

RUN GO111MODULE=on go get -u -v github.com/projectdiscovery/httpx/cmd/httpx \
    github.com/projectdiscovery/naabu/cmd/naabu \
    github.com/projectdiscovery/subfinder/cmd/subfinder \
    github.com/lc/gau \
    github.com/projectdiscovery/nuclei \
    github.com/lc/subjs \
    github.com/projectdiscovery/shuffledns/cmd/shuffledns

RUN GO111MODULE=on go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
RUN apt-get install -y curl host

COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

RUN git clone https://github.com/blechschmidt/massdns.git
RUN cd massdns; make
RUN cp massdns/bin/massdns /root/go/bin

RUN  apt install chromium-browser -y
RUN  apt-get install -y xvfb

RUN mkdir /app
WORKDIR /app


COPY . /app/
RUN mkdir /app/nuclei-templates
RUN git clone https://github.com/projectdiscovery/nuclei-templates.git /app/nuclei-templates

RUN chmod +x boot.sh
RUN /app/boot.sh
RUN chmod +x /app/run.sh
RUN python3 /app/exec.py
EXPOSE 5000
ENTRYPOINT [ "/app/run.sh" ] 

#CMD ["/app/app.py"]
