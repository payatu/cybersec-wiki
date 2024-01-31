# API application

This Cheat sheet focus on Installing different Vulnerable Web API applications that build with different  technology stacks like Java, Nodejs, PHP and Python

Easier for peoples to download and install in different ways through Docker, Vagrant, VM, Manual, and Host in local machine. 

## Java Vulnerable API

- [Completely ridiculous API [crAPI]](https://github.com/OWASP/crAPI)
    - **Docker**
        1. `git clone https://github.com/OWASP/crAPI.git`
        2. `cd crAPI`
        3. `curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml`
        4. `docker-compose pull`
        5. `docker-compose -f docker-compose.yml --compatibility up -d`
        6. Browse [`http://localhost:8888`](http://localhost:8888)
    - **Vagrant**
        1. `git clone https://github.com/OWASP/crAPI.git`
        2. `cd deploy/vagrant && vagrant up`
        3. Browse http://192.168.33.20/ 


## Python Vulnerable API

- [Damn Vulnerable GraphQL Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application)
    - **Docker Image**
        1. `git clone https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application.git && cd Damn-Vulnerable-GraphQL-Application`
        2. `docker build -t dvga .`
        3. `docker build -t dvga -f Dockerfile.arm64 .`
        4. `docker run -d -t -p 5013:5013 -e WEB_HOST=0.0.0.0 --name dvga dvga`
        5. Browse http://localhost:5013/ 
    - **Docker Hub**
        1. `docker pull dolevf/dvga`
        2. `docker run -t -p 5013:5013 -e WEB_HOST=0.0.0.0 dolevf/dvga`
        3. Browse http://localhost:5013/ 
    - **Host in local machine**
        1. `cd /opt/`
        2. `git clone [git@github.com](mailto:git@github.com):dolevf/Damn-Vulnerable-GraphQL-Application.git && cd Damn-Vulnerable-GraphQL-Application`
        3. `pip3 install -r requirements.txt`
        4. `python3 [app.py](http://app.py/)`
        5. Browse http://localhost:5013/ 

- [Payatu Tiredful-API](https://github.com/payatu/Tiredful-API)
    - **Docker**
        1. `git clone https://github.com/payatu/Tiredful-API.git` 
        2. `cd Tiredful-API`
        3. `docker build -t tiredful .`
        4. `docker run -p 8000:8000 --name tiredful -it tiredful`
        5. Browse http://localhost:8000/ 


## PHP Vulnerable API

- [vAPI](https://github.com/roottusk/vapi)
    
    - **Docker**
        1. `git clone https://github.com/roottusk/vapi.git`
        2. `cd vapi`
        3. `docker-compose up -d`

    - **Online Postman**
        1. https://www.postman.com/roottusk/workspace/vapi/overview 

- [Generic University Vulnerable API](https://github.com/InsiderPhD/Generic-University)
    - **Docker Hub**
        1. `docker pull busk3r/genericuniversity:latest`
        2. `docker run --name genericuniversity -itd --rm -p 80:8000 busk3r/genericuniversity && docker exec genericuniversity service mysql start && docker exec genericuniversity mysql -u root -p -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'password';”`
        3. `docker exec genericuniversity php /root/Generic-University/artisan serve --host 0.0.0.0`
        4. Browse http://localhost 


## Nodejs Vulnerable API

- [Damn Vulnerable Web Service](https://github.com/snoopysecurity/dvws-node)
    - **Docker**
        1. `git clone https://github.com/snoopysecurity/dvws-node.git`
        2. `cd dvws-node`
        3. `docker-compose up`
        4. Browse http://localhost 
    - **Manual**
        1. `docker run -d -p 27017-27019:27017-27019 --name dvws-mongo mongo:4.0.4`
        2. `docker run -p 3306:3306 --name dvws-mysql -e MYSQL_ROOT_PASSWORD=mysecretpassword -e MYSQL_DATABASE=dvws_sqldb -d mysql:8`
        3. `git clone https://github.com/snoopysecurity/dvws-node.git`
        4. `cd dvws-node`
        5. `sudo apt-get install -y libxml2 libxml2-dev`
        6. `npm install --build-from-source`
        7. `node startup_script.js`
        8. `sudo npm start`
        9. Browse http://localhost