# Web application 

This Cheat sheet focus on Installing different Vulnerable Web applications that build with different  technology stacks like Java, Nodejs, PHP and Python [Contains 30+ Vulnerable Applications]

Easier for peoples to download and install in different ways through Docker, Vagrant, VM, Manual, and Host in local machine. 

## Java Vulnerable Applications

- [Web Goat](https://github.com/WebGoat/WebGoat)
    - **Host in local machine**
        1. download jar file: https://github.com/WebGoat/WebGoat/releases/download/v2023.4/webgoat-2023.4.jar
        2. `java -jar webgoat<branchname>`
        3. Browse `localhost:8080/WebGoat`
        4. Register & start practicing
    - **Docker**
        1. `docker pull webgoat/goatandwolf`
        2. `docker run -it -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat`
        3. Browse [`http://127.0.0.1:8080/WebGoat`](http://127.0.0.1:8080/WebGoat)
        4. As long as we don't remove the container we can use: `docker start webgoat`
- [Bodgelt Store](https://github.com/psiinon/bodgeit)
    - **Docker**
        1. `docker pull psiinon/bodgeit`
        2. `docker run --rm -p 8080:8080 -i -t psiinon/bodgeit`
        3. Browse `http://127.0.0.1:8080/bodgeit`
        4. As long as we don’t remove the container we can use: `docker start bodgeit`
- [EasyBuggy](https://github.com/k-tamura/easybuggy)
    - **Docker**
        1. Download **easybuggy** locally 
        2. `docker build . -t easybuggy:local`
        3. `docker run -p 8080:8080 easybuggy:local`
        4. `Browse http://127.0.0.1:8080`
        5. To stop `https://127.0.0.1:8080/exit`
- [Marathon](https://github.com/cschneider4711/Marathon)
    - **Docker**
        1. Download locally 
        2. `docker build -f Dockerfile-local -t marathon:latest .`
        3. If any issues, run `npm audit`
        4. `docker run --rm --name marathon-8080 -p 127.0.0.1:8080:8080 --cpu-shares="256" --memory-reservation="512m" --memory="1g" marathon:latest`
        5. Browse [`http://localhost:8080/marathon](http://localhost:8080/marathon)` 
        6. Access the page [`http://localhost:8080/marathon/showMarathons.page`](http://localhost:8080/marathon/showMarathons.page)
        7. Create account and start hacking 
- [OWASP Vulnerable App](https://github.com/SasanLabs/VulnerableApp)
    - **Docker**
        1. Clone the repo `git clone https://github.com/SasanLabs/VulnerableApp.git` 
        2. `cd VulnerableApp`
        3. `docker-compose pull && docker-compose up`
        4. Browse `http://localhost`
    - **Host in local machine**
        1. Download Jar file https://github.com/SasanLabs/VulnerableApp/releases/download/1.11.0/VulnerableApp-1.11.0.jar
        2. Navigate to the project directory 
        3. `java -jar VulnerableApp-*`
        4. Browse [`http://localhost:9090/VulnerableApp`](http://localhost:9090/VulnerableApp)
- [Security Shepherd](https://github.com/OWASP/SecurityShepherd/)
    - **Docker**
        1. `git clone https://github.com/OWASP/SecurityShepherd.git`
        2. `cd SecurityShepherd` 
        3. `sudo gpasswd -a $USER docker`
        4. `mvn -Pdocker clean install -DskipTests`
        5. `docker-compose up`
        6. Browse http://localhost [admin:password]
    - **Virtual Box**
        1. Download file - https://github.com/OWASP/SecurityShepherd/releases/download/v3.1/owaspSecurityShepherd_v3.1_VM.zip
        2. Import the file in VM 
        3. Start the machine
        4. Login with default credentials included in the VM Download .txt file {(user: securityshepherd pass: shepherd3.1)}
        5. Check your IP address with `ifconfig`
        6. Browse `http://<yourip>`
        7. Start hacking 
- [Vulnerable Java Web application](https://github.com/CSPF-Founder/JavaVulnerableLab/)
    - **Docker**
        1. `git clone https://github.com/CSPF-Founder/JavaVulnerableLab.git`
        2. `cd JavaVulnerableLab`
        3. `sudo docker-compose up`
        4. Browse [`http://localhost:8080/JavaVulnerableLab/install.jsp](http://localhost:8080/JavaVulnerableLab/install.jsp)` 
        5. Click on the Install button
    - **Virtual Box**
        1. Download file - https://sourceforge.net/projects/javavulnerablelab/files/v0.1/JavaVulnerableLab.ova/download 
        2. Import the **JavaVulnerable.ova** into VirtualBox
        3. Change the Network Settings to Host-Only Network
        4. Start the Machine and Log into the Machine( Credentials→ Username: root, Password: cspf)
        5. Start Tomcat by entering "`service tomcat start`" in the Terminal
        6. Start MySQL by entering "`service mysql start`" in the Terminal
        7. Find the IP Address of Machine - `ifconfig`
        8. In your Browser, go to "`http://[IP_ADDRESS_OF_VM]:8080/JavaVulnerableLab/install.jsp`
        9. Click the Install Button
    - **Host in local machine**
        1. Download Jar file `http://sourceforge.net/projects/javavulnerablelab/files/v0.2/JavaVulnerableLab.jar/download` 
        2. Navigate to the project directory
        3. Run `java -jar JavaVulnerableLab.jar`
        4. Browse `http://localhost:8080/JavaVulnerableLab/install.jsp`

## Nodejs Vulnerable Applications

- [Juice shop](https://github.com/juice-shop/juice-shop)
    - **Host it in local Machine**
        1. Install [node.js](https://github.com/juice-shop/juice-shop#nodejs-version-compatibility)
        `apt install npm`
        2. `git clone https://github.com/juice-shop/juice-shop.git` 
        3. `cd juice-shop`
        4. `npm install`
        5. `npm start` 
        6. Browse to [http://localhost:3000](http://localhost:3000/)
            
    - **Docker**
        1. Install [Docker](https://www.docker.com/) - https://docs.docker.com/desktop/install/debian/
        2. Run `docker pull bkimminich/juice-shop`
        3. Run `docker run --rm -p 3000:3000 bkimminich/juice-shop`
        4. Browse to [http://localhost:3000](http://localhost:3000/)
            
    - **Vagrant**
        1. Install [Vagrant](https://www.vagrantup.com/downloads.html) and [Virtualbox](https://www.virtualbox.org/wiki/Downloads)
        2. Run `git clone https://github.com/juice-shop/juice-shop.git`
        3. Run `cd vagrant && vagrant up`
        4. Browse to [192.168.56.110](http://192.168.56.110/)
- [Damn Vulnerable Nodejs Application](https://github.com/appsecco/dvna?tab=readme-ov-file)
    - **Docker**
        1. `docker run --name dvna -p 9090:9090 -d appsecco/dvna:sqlite`
        2. Browse http://127.0.0.1:9090/ 
    - **Docker Hub**
        1. `git clone https://github.com/appsecco/dvna; cd dvna`
        2. Create one ‘vars.env’ file with this cred
        
        ```jsx
        MYSQL_USER=dvna
        MYSQL_DATABASE=dvna
        MYSQL_PASSWORD=passw0rd
        MYSQL_RANDOM_ROOT_PASSWORD=yes
        ```
        
        1. `docker-compose up`
        2. Browse [`http://127.0.0.1:9090/](http://127.0.0.1:9090/)` 
    - **Manual Step**
        1. `git clone https://github.com/appsecco/dvna; cd dvna`
        2. Configure the environment variables with your database information
        
        ```jsx
        export MYSQL_USER=dvna
        export MYSQL_DATABASE=dvna
        export MYSQL_PASSWORD=passw0rd
        export MYSQL_HOST=127.0.0.1
        export MYSQL_PORT=3306
        ```
        
        1. `npm install`
        2. `npm start`
        3. Access the application at [http://localhost:9090](http://localhost:9090/)
- [Extreme Vulnerable Node Application](https://github.com/vegabird/xvna)
    - **Host in local machine**
        1. Download the zip file - https://github.com/vegabird/xvna/blob/master/xvna.zip 
        2. Start MongoDB
        3. Create DB **xvna** in MongoDB
        4. Import the Collection to MongoDB given from folder collection
        5. Start the **xvna** from root folder using command: `node index.js`
        6. Hit “http://localhost:3000/app”
        7. Login Credential: **Email**-> [admin@xvna.com](mailto:admin@xvna.com), **Password** -> password
- [Node Goat](https://github.com/OWASP/NodeGoat)
    - **Docker**
        1. `git clone https://github.com/OWASP/NodeGoat.git`
        2. `cd NodeGoat`
        3. `docker-compose build`
        4. `docker-compose up`
        5. `Browse http://localhost:4000/` 
    - **Host in local machine**
        1. `git clone https://github.com/OWASP/NodeGoat.git`
        2. `cd NodeGoat`
        3. `npm install`
        4. Browse “http://localhost”
- [Snyk’s Goof](https://github.com/snyk-labs/nodejs-goof)
    - **Docker compose**
        1. `git clone ‣` 
        2. `cd nodejs-goof`
        3. `docker-compose up --build`
        4. `docker-compose down`
        5. Browse http://localhost:3001/ 
    - **Docker**
        1. `git clone https://github.com/snyk-labs/nodejs-goof.git` 
        2. `cd nodejs-goof`
        3. `docker run --rm -p 27017:27017 mongo:3`
- [Vulnerable Node](https://github.com/cr0hn/vulnerable-node)
    - **Docker**
        1. `git clone https://github.com/cr0hn/vulnerable-node.git vulnerable-node`
        2. `cd vulnerable-node/`
        3. `docker-compose build && docker-compose up`
        4. Browse [localhost:3000](http://localhost:3000) 
        5. Start hacking
- [Payatu Vulnerable Nodejs Application](https://github.com/payatu/vuln-nodejs-app)
    - **Docker**
        1. `git clone https://github.com/payatu/vuln-nodejs-app.git`
        2. `cd ./vuln-nodejs-app`
        3. `docker-compose up --build -d`
        4. `docker-compose up -d`
        5. Browse http://localhost:9000/ 
    - **Manual**
        1. `git clone https://github.com/payatu/vuln-nodejs-app.git`
        2. `cd ./vuln-nodejs-app`
        3. Create Database
            
            $ `mysql -u <mysql_user> -p`
            mysql> `create database vuln_nodejs_app;`
            
        4. Update your MySQL and MongoDB database username and password inside **.env** file.
            
            ```jsx
            DB_PORT=3306
            DB_NAME=vuln_nodejs_app
            DB_USER=vuln_nodejs_user
            DB_PASS=passw0rd
            HOST_PORT=9000
            JWT_SECRET=secret
            MONGODB_SERVER=localhost
            MONGODB_ADMINUSERNAME=
            MONGODB_ADMINPASSWORD=
            ```
            
        5. `npm install`
        6. `npm run build`
        7. `node server.js`
        8. Browse http://localhost:9000/ 



## PHP Vulnerable Applications

- [Mutillidae](https://github.com/webpwnized/mutillidae)
    - **Dockerhub images**
        1. `git clone https://github.com/webpwnized/mutillidae-dockerhub.git` 
        2. `cd mutilldae-dockerhub`
        3. Installation → https://docs.docker.com/compose/install/
        4. `docker-compose up` 
        5. Now browse “http://127.0.0.1“
            1. Click on ‘Reset DB’ button
                - Port 80, 8080: Mutillidae HTTP web interface
                - Port 81: MySQL Admin HTTP web interface
                - Port 82: LDAP Admin web interface
                - Port 443: HTTPS web interface
                - Port 389: LDAP interface
        6. Import **ldap** file in web application at port 82 (https://github.com/webpwnized/mutilidae/blob/master/configuration/openldap/mutilidae.ldif)
    - **Docker**
        1. `git clone [https://github.com/webpwnized/mutillidae-docker.git](https://github.com/webpwnized/mutillidae-dockerhub.git)` 
        2. `cd mutilldae-docker`
        3. `docker-compose up` 
        4. Now browse 127.0.0.1 
            - Port 80, 8080: Mutillidae HTTP web interface
            - Port 81: MySQL Admin HTTP web interface
            - Port 82: LDAP Admin web interface
            - Port 443: HTTPS web interface
            - Port 389: LDAP interface
    - **XAMPP**
        1. Download and Install XAMPP https://www.apachefriends.org/download.html
        2. `cd Downloads` 
        3. `chmod +x xampp-linux-x64-8.2.4-0-installer.run`
        4. `./xampp-linux-x64-8.2.4-0-installer.run`
        5. Take note that XAMPP is installed on **/opt/lampp**
        6. Now download Mutillidae (https://github.com/webpwnized/mutillidae)
        7. Copy the entire Mutillidae directory to **/opt/lampp/htdocs** `cp -r mutillidae /opt/lampp/htdocs`
        8. Change directory to /opt/lampp `cd /opt/lampp`
        9. Start the XAMPP `sudo ./xampp start`
        10. Now browse **http://[Kalilinx IP Address]/mutillidae**
- [bWAPP](https://github.com/raesene/bWAPP)
    - **XMAPP**
        1. Download and Install XMAPP https://www.apachefriends.org/download.html
        2. `cd Downloads` 
        3. `chmod +x xampp-linux-x64-8.2.4-0-installer.run`
        4. `./xampp-linux-x64-8.2.4-0-installer.run`
        5. Take note that XAMPP is installed on /opt/lampp
        6. Now download bWAPP
        7. `cp -r bWAPP /opt/lampp/htdocs`
        8. start the xmapp `sudo ./xampp start`
        9. Now browse **http://[Kalilinx IP Address]/mutillidae**
    - **Virtual box**
        1. Download the bWAPP https://sourceforge.net/projects/bwapp/files/bee-box/
        2. Extract the zip file 
        3. Open Virtualbox. Add new machine.
        4. Select the machine folder (to store VM files) and input name for the new machine. Choose Type → **Linux, 64-bit**
        5. Next and choose **Use an existing hard disk** and choose the folder for download BeeBox file.
        6. Now choose **bwapp.vmdk** in Hard disk selector
        7. Start and Run  
- [DVWA](https://github.com/digininja/DVWA)
    - **XAMPP Linux**
        1. Download and Install XAMPP https://www.apachefriends.org/download.html
        2. `cd Downloads` 
        3. `chmod +x xampp-linux-x64-8.2.4-0-installer.run`
        4. `./xampp-linux-x64-8.2.4-0-installer.run`
        5. Take note that XAMPP is installed on /opt/lampp
        6. Now download DVWA (https://github.com/digininja/DVWA)
        7. Copy the complete DVWA directory to /opt/lampp/htdocs → `cp -r dvwa /opt/lampp/htdocs`
        8. Change the directory to /opt/lampp
        9. Start the XAMPP `sudo ./xampp start`
        10. Now browse **http://[Kalilinx IP Address]/dvwa**
    - **Local machine**
        1. `git clone https://github.com/digininja/DVWA.git`
        2. `mv DVWA /var/www/html`
        3. `service apache2 start` Might be required to use ‘sudo’
        4. Now browse [localhost/DVWA](http://localhost/DVWA) in Web browser
        5. Shows error
        6. `cd /var/www/html`
        7. `cd DVWA`
        8. `cp config/config.inc.php.dist config/config.inc.php`
        9. `service mariadb start`
        10. Type **sql** and click enter → `sql`
        11. Enter the queries in the database
        - `mysql> create database dvwa;`
        - `create user dvwa@localhost identified by 'p@ssw0rd';`
        - `grant all on dvwa.* to dvwa@localhost;`
        - `mysql> flush privileges;`
        1. Now the login page will be visible and access **localhost/DVWA/login.php**
    - **Docker**
        1. Download DVWA https://github.com/digininja/DVWA#download
        2. Extract the file 
        3. `cd DVWA`
        4. `docker compose up -d`
        5. Now browse [http://localhost:4280](http://localhost:4280/)
- [WackoPicko](https://github.com/adamdoupe/WackoPicko)
    - **Docker**
        1. `docker run -p 127.0.0.1:8080:80 -it adamdoupe/wackopicko`
        2. Browse `localhost:8080`
- [Bricks](https://sechow.com/bricks/index.html)
    - **UWAMP**
        1. Download UWAMP - https://www.uwamp.com/file/UwAmp.rar
        2. Download Bricks - https://sechow.com/bricks/download.html 
        3. Unzip both
        4. Move the bricks folder to ‘uwamp’
        5. Open **uwamp** and start & click phpmyadmin
        6. Create new database named **Bricks**
        7. Now access the “http://localhost/bricks”
        8. Start hacking
        9. Follow link : https://www.youtube.com/watch?v=hcKAKu5FIhM 
- [Conviso Vulnerable Web Application [CVWA]](https://github.com/convisolabs/CVWA)
    - **Docker**
        1. `git clone https://github.com/convisolabs/CVWA`
        2. `cd CVWA`
        3. `docker build -t cvwa .`
        4. `docker container run -ti -p 8080:80 cvwa`
        5. Browse http://localhost:8080/site/index.php 
- [Deliberately Insecure Web Application [DIWA]](https://github.com/snsttr/diwa)
    - **Host in local machine**
        1. `git clone ‣` 
        2. `cd diwa`
        3. `composer install`
        4. `cd app`
        5. `php -S 127.0.0.1:80 -t .`
        6. Browse [`http://localhost`](http://localhost📼)
    - **Docker**
        1. `git clone ‣`
        2. `cd diwa`
        3. `docker build -t diwa .`
        4. `docker run -p 8080:80 -d diwa:latest`
        5. Browse [`http://localhost:8080/`](http://localhost:8080/)
- [OSTE](https://github.com/OSTEsayed/OSTE-Vulnerable-Web-Application)
    - **Host in local machine**
        1. `git clone https://github.com/OSTEsayed/OSTE-Vulnerable-Web-Application.git` 
        2. Copy the entire directory to /opt/lampp/htdocs `cp -r OSTE-Vulnerable-Web-Application /opt/lampp/htdocs`
        3. Change the directory `cd /opt/lampp`
        4. Start the XAMPP `sudo ./xampp start`
        5. Now browse `http://<Kali IP Address>/OSTE-Vulnerable-Web-Application` 
- [SSRF Vulnerable App](https://github.com/incredibleindishell/SSRF_Vulnerable_Lab)
    - **Docker**
        1. `git clone https://github.com/incredibleindishell/SSRF_Vulnerable_Lab.git` 
        2. `cd SSRF_Vulnerable_Lab` 
        3. `docker build .`
        4. `docker run -p 9000:80` 
        5. Browse `http://localhost:9000`
- [Unsafe Bank](https://github.com/lucideus-repo/UnSAFE_Bank)
    - **Host in local machine**
        1. `git clone https://github.com/lucideus-repo/UnSAFE_Bank.git`
        2. `cd UnSAFE_Bank/Backend`
        3. `docker-compose up -d`
        4. Browse (http://localhost:3000)` 
- [VulnLab](https://github.com/Yavuzlar/VulnLab)
    - **Docker**
        1. `docker run --name vulnlab -d -p 1337:80 yavuzlar/vulnlab:latest`
        2. Browse [`http://localhost:1337/](http://localhost:1337/)` 
    - **Manual**
        1. `git clone https://github.com/Yavuzlar/VulnLab`
        2. `cd Vulnlab`
        3. `docker build -t yavuzlar/vulnlab .`
        4. `docker run -d -p 1337:80 yavuzlar/vulnlab`
        5. Browse [`http://localhost:1337/](http://localhost:1337/)` 
- [Xtreme Vulnerable Web Application [XVWA]](https://github.com/s4n7h0/xvwa)
    - **Docker**
        1. `sudo docker run --name xvwa -d -p 80:80 tuxotron/xvwa`
        2. Browse [`http://localhost/xvwa`](http://localhost/xvwa)
    - **Automatic installation Scripts**
        1. Run this bash script in root folder - https://github.com/s4n7h0/Script-Bucket/blob/master/Bash/xvwa-setup.sh 
        2. Browse [`http://localhost/xvwa`](http://localhost/xvwa)
    - **Manual**
        1. Clone the repo https://github.com/s4n7h0/xvwa
        2. Move it to your webserver path 
        3. Database configuration - `xvwa/config.php`
        4. Browse [`http://localhost/xvwa/`](http://localhost/xvwa/)
        5. Reset or setup - [`http://localhost/xvwa/setup/`](http://localhost/xvwa/setup/)

## Python Vulnerable Applications 
- [Damn Small Vulnerable Web [DSVW]](https://github.com/stamparm/DSVW)
    - **Run in Host machine**
        1. `git clone https://github.com/stamparm/DSVW.git`
        2. `cd DSVW` 
        3. `pip install -r requirements.txt`
        4. `python3 dsvw.py`
        5. Browse [`http://localhost:65412`](http://localhost:65412)
- [Damn Vulnerable Python Web App [DVPWA]](https://github.com/anxolerd/dvpwa)
    - **Docker**
        1. `git clone https://github.com/anxolerd/dvpwa.git` 
        2. `cd dvpwa`
        3. `pip install -r requirements.txt`
        4. `docker-compose up -d`
        5. Browse [`http://localhost:8080/`](http://localhost:8080/)
- [Pygoat](https://github.com/adeyosemanputra/pygoat)
    - **Docker**
        1. `docker pull pygoat/pygoat:latest`
        2. `docker run --rm -p 8000:8000 pygoat/pygoat:latest`
        3. Browse [`http://127.0.0.1:8000/`](http://127.0.0.1:8000/)
    - **Docker Compose**
        1. `git clone https://github.com/adeyosemanputra/pygoat.git` 
        2. `cd pygoat`
        3. `docker-compose up -d`
        4. Browse [`http://127.0.0.1:8000/`](http://127.0.0.1:8000/)
    - **Docker Image**
        1. `git clone https://github.com/adeyosemanputra/pygoat.git` 
        2. `cd pygoat`
        3. `docker build -f Dockerfile -t pygoat .`
        4. `docker run --rm -p 8000:8000 pygoat:latest`
        5. Browse [`http://127.0.0.1:8000/`](http://127.0.0.1:8000/)
    - **Manual**
        1. `git clone https://github.com/adeyosemanputra/pygoat.git`
        2. `cd pygoat`
        3. `pip install -r requirements.txt`
        4. `python3 [manage.py](http://manage.py/) migrate`
        5. `python3 [manage.py](http://manage.py/) runserver`
        6. Browse [`http://127.0.0.1:8000/`](http://127.0.0.1:8000/)
- [Vulnerable SAML App](https://github.com/yogisec/VulnerableSAMLApp)
    - **Docker**
        1. `git clone https://github.com/yogisec/VulnerableSAMLApp.git` 
        2. `cd VulnerableSAMLApp`
        3. `docker-compose up`
        4. Browse [`http://127.0.0.1:8000/`](http://127.0.0.1:8000/)



## Direct Online Practice
1. [Acunetix](http://testphp.vulnweb.com/)
2. [Altoro Mutual](http://demo.testfire.net/)
3. [BGA Vulnerable BANK App](http://www.bgabank.com/) 
4. [Cyber Scavenger Hunt](https://cyberscavengerhunt.com/) 
5. [Defend the Web](https://defendtheweb.net/) 
6. [Gin & Juice Shop](https://ginandjuice.shop/) 
7. [Gruyere](https://google-gruyere.appspot.com/) 
8. [HackThisSite](https://www.hackthissite.org/) 
9. [HackXpert](https://labs.hackxpert.com/) 
10. [HackYourselfFirst](https://hack-yourself-first.com/) 
11. [Hacking Lab](https://www.hacking-lab.com/events/) 
12. [Netsparker Test App .NET](http://aspnet.testsparker.com/) 
13. [Netsparker Test App PHP](http://php.testsparker.com/) 
14. [OWASP Juice Shop](https://owasp-juice.shop/) 
15. [Security Tweets](http://testhtml5.vulnweb.com/) 
16. [Zero Bank](http://zero.webappsecurity.com/) 
17. [hackxor](http://hackxor.sourceforge.net/cgi-bin/index.pl)