# Preparación para entrevistas DevOps
El propósito de este documento es prepara una serie de temas que puedan ayudar a la comunidad que quiera iniciarse en posiciones como SRE o DevOps Engineer.

## Como contribuir
Si tienes un tema que pueda ayudar o encuentras algún error, por favor manda un PR con el cambio!

# AWS
## S3
- Como se asignan permisos
  - https://docs.aws.amazon.com/AmazonS3/latest/user-guide/set-permissions.html 

- Diferencia entre los distintos tipos de storage classes
  - https://aws.amazon.com/s3/storage-classes/ 
- Que es "Object Storage" y sus casos de uso
- Diferencia entre "Object Storage" y "Block Storage"
- Se puede usar para dar de alta un sitio web estático
- Como funcionan los triggers y sus casos de uso

## EC2
- Security groups (Es como el firewall de instancias)
  - https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html 

## EBS
- Que es "Block Storage" y sus casos de uso
- Diferencia entre "Object Storage" y "Block Storage"
- Como crear un volumen
- Como sacar snapshots
- Clases de almacenamiento
  - https://aws.amazon.com/ebs/volume-types/ 

## Autoscaling groups
- Usar un autoscaling group con load balancer
  - https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-load-balancer.html 
  - https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-register-lbs-with-asg.html 

## Load balancers
- Revisar diferencias entre los tipos de LB LB y casos de uso
  - https://aws.amazon.com/elasticloadbalancing/ 
- Conocer en que casos usar ALB y NLB
  - ELB/ALB: Se usan para trafico HTTP/HTTPS (Layer 7)
  - NLB: Se usan para tráfico TCP o UDP (Layer 4)

## RDS
- Información general y que tipos de bases soportan
  - https://aws.amazon.com/rds/ 
- Como hacer un failover a otra AZ
  - https://aws.amazon.com/rds/features/multi-az/ 

## Route53
- Información general
  - https://aws.amazon.com/route53/ 
- Tipos de registros soportados (Aprender al menos los A, AAAA, NS, MX, CNAME)
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html 
- Que es un Alias
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html 

## CloudFormation
- Información general
  - https://medium.com/faun/getting-hands-dirty-with-aws-cloudformation-c20e44ea994e 
- Formatos soportados
  - YAML
  - JSON

## VPC
- Cada subnet esta asignada a una AZ (Zona de disponibilidad)
- La diferencia entre una subnet pública y una privada es que la subnet pública tiene asignado un Internet Gateway (IGW)

## ECS
- Que es
  - https://aws.amazon.com/ecs/ 
- Conceptos
  - Service Definition
  - Task Definition

## ECR
- Que es
  - https://aws.amazon.com/ecr/ 
  - https://aws.amazon.com/es/ecr/getting-started/
- Comandos básicos
  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/getting-started-cli.html

## EKS
- Configurar acceso a otros usuarios mediante configmap/aws-auth
  - https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html 
- worker groups
  - https://docs.aws.amazon.com/eks/latest/userguide/worker.html 
- node groups
  - https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html 
- Autoscaling
  - https://docs.aws.amazon.com/eks/latest/userguide/cluster-autoscaler.html 

## CloudWatch
- Para qué sirve
  - https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html 

## CloudTrail
- Para qué sirve
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html

# GCP
## Compute Engine
- Información general:
  - https://cloud.google.com/compute/ 
- Como sacar snapshots de discos
- Como configurar IP estática

## Kubernetes Engine
- Información general
  - https://cloud.google.com/kubernetes-engine/ 
- Como desplegar un cluster y conectarse
  - https://www.youtube.com/watch?v=FXOSL5vHBF4 
- GCE Loadbalancer
  - https://cloud.google.com/kubernetes-engine/docs/tutorials/http-balancer 
- GCE Managed certificates
  - https://cloud.google.com/kubernetes-engine/docs/how-to/managed-certs 

## Container Registry
- Que es
  - https://cloud.google.com/container-registry 
- Como se usa
  - https://cloud.google.com/container-registry/docs/pushing-and-pulling 

## Load Balancing
- Información general
 - https://cloud.google.com/load-balancing/
- Como elegir el tipo de loadbalancer
  - Global Load Balancer: HTTP/HTTPS (Layer 7)
  - Network Load Balancer: TCP/UDP (Layer 4)
  - https://cloud.google.com/load-balancing/docs/choosing-load-balancer/
- Cloud Armor
  - https://cloud.google.com/armor 
  - Compatible con Global Load Balancer
  - Protege contra bots y SQLi

## Cloud DNS
- Información general
  - https://cloud.google.com/dns/docs/overview 

## Cloud SQL
- Información general
  - https://cloud.google.com/sql/docs/ 
- Soporta IP pública y privada
- Como dar de alta acceso a IPs públicas

## Cloud Storage
- Información general
  - https://cloud.google.com/storage/ 
- Clases de almacenamiento
- Casos de uso y cuando usar cada clase de almacenamiento
- Se puede usar para dar de alta un sitio web estático
- Se puede conectar a un Loadbalancer

## Cloud NAT
- Información general
  - https://cloud.google.com/nat/ 
- No es compatible con Cloud VPN para acceder puntos remotos desde una sola IP

## Cloud VPN
- Información general
  - https://cloud.google.com/network-connectivity/docs/vpn/concepts/overview 

## VPC
- Como configurar reglas de acceso
- Las subnets son regionales
- Diferencia entre redes default, automatic y custom
  - Default: Se crea una por proyecto de forma automática, una subnet por region y reglas de firewall automáticas
  - Automatic: Una subnet por region y reglas de firewall automáticas
  - Custom
    - No crea subnets
    - No crea reglas de firewall
- Google Private Access
  - https://cloud.google.com/vpc/docs/private-access-options
- Google Service Access
  - https://cloud.google.com/vpc/docs/private-services-access

# Automatización de configuración e infraestructura
## Terraform
- Como funciona
  - https://openwebinars.net/blog/por-que-usar-terraform/
- Como crear instancias en AWS
  - https://learn.hashicorp.com/collections/terraform/aws-get-started 
  - https://www.terraform.io/docs/providers/aws/r/instance.html 
  - https://blog.valouille.fr/post/2018-03-22-how-to-use-terraform-to-deploy-an-alb-application-load-balancer-with-multiple-ssl-certificates/ 
- Desplegar infraestructura en DigitalOcean
  - https://www.digitalocean.com/community/tutorials/how-to-use-terraform-with-digitalocean 

## Ansible
- Conceptos básicos
  - playbook
  - roles
- Comandos básicos
  - https://www.digitalocean.com/community/tutorials/how-to-use-ansible-cheat-sheet-guide 

## Puppet (No recomendado)
- https://www.digitalocean.com/community/tutorials/how-to-install-puppet-to-manage-your-server-infrastructure

# Contenedores y orquestación
## Docker
- Como hacer imágenes Docker
  - https://docs.docker.com/get-started/ 
  - Como migrar aplicaciones a Docker
- Estructura de un Dockerfile
  - FROM
  - RUN
  - WORKDIR
  - COPY
  - COMMAND
  - ENV
  - ARG
  - EXPOSE
- Crear imagen desde cero
  - https://www.mgasch.com/post/scratch/ 
- Comandos básicos
  - docker login
  - docker build
  - docker pull
  - docker push
  - docker tag
  - docker run
  - docker exec
  - docker cp
  - docker logs
  - docker image
  - docker rm
- Como usar docker-compose
  - https://docs.docker.com/compose/ 
- Optimización
  - No usar múltiples RUN
- Como funciona el docker multistage
  - https://docs.docker.com/develop/develop-images/multistage-build/ 
- Docker registry
  - docker hub
  - gcr
  - ecr
  - nexus

## Kubernetes
- Información general
  - https://kubernetes.io/ 
- Conceptos básicos
  - pod
  - deployment
  - statefulset
  - daemonset
  - service
    - información
      - https://medium.com/google-cloud/kubernetes-nodeport-vs-loadbalancer-vs-ingress-when-should-i-use-what-922f010849e0 
    - Tipos
      - ClusterIP
      - NodePort
      - Loadbalancer
  - ingress
    - https://www.digitalocean.com/community/tutorials/how-to-set-up-an-nginx-ingress-with-cert-manager-on-digitalocean-kubernetes
  - namespace
  - configmap
  - secrets
  - readinessprobe / livenessprobe
    - https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/
  - pv (Persistent Volume
  - pvc (Persistent Volume Claim)
  - netpol (Network Policy)
    - https://github.com/ahmetb/kubernetes-network-policy-recipes
  - hpa (Horizontal Pod Autoscaler)
    - https://www.paradigmadigital.com/dev/kubernetes-autoescalado-horizontal-pods-custom-metrics/
- Como asignar pods a un nodo
  - nodeSelector
  - affinity
- Como descargar imagenes desde un registry privado
- Como agregar variables a un pod
  - env
    - https://www.magalix.com/blog/kubernetes-patterns-environment-variables-configuration-pattern 
    - https://kubernetes.io/docs/tasks/inject-data-application/define-environment-variable-container/ 
  - configmap
    - https://www.magalix.com/blog/kubernetes-patterns-environment-variables-configuration-pattern 
    - https://matthewpalmer.net/kubernetes-app-developer/articles/ultimate-configmap-guide-kubernetes.html 
  - secrets
    - https://opensource.com/article/19/6/introduction-kubernetes-secrets-and-configmaps 
- Como desplegar Kubernetes
  - https://k3s.io/ 
  - https://rancher.com/docs/rke/latest/en/ 
  - https://kubernetes.io/docs/setup/production-environment/tools/kubespray/ 
  - https://microk8s.io/ 
- Comandos básicos
  - kubectl get namespace: Listar namespaces
  - kubectl -n namespace get: mostrar recursos
    - kubectl -n namespace get nodes
    - kubectl -n namespace get namespace
    - kubectl -n namespace get configmap
    - kubectl -n namespace get secrets
    - kubectl -n namespace get pods
    - kubectl -n namespace get deployment
    - kubectl -n namespace get statefulset
    - kubectl -n namespace get daemonset
    - kubectl -n namespace get service
    - kubectl -n namespace get ingress
    - kubectl -n namespace get netpol
  - kubectl -n namespace describe: mostrar información detallada de recursos
    - kubectl -n namespace describe nodes
    - kubectl -n namespace describe namespace
    - kubectl -n namespace describe configmap
    - kubectl -n namespace describe secrets
    - kubectl -n namespace describe pods
    - kubectl -n namespace describe deployment
    - kubectl -n namespace describe statefulset
    - kubectl -n namespace describe daemonset
    - kubectl -n namespace describe service
    - kubectl -n namespace describe ingress
    - kubectl -n namespace describe netpol
  - kubectl -n namespace delete: Eliminar recursos
    - kubectl -n namespace delete nodes
    - kubectl -n namespace delete namespace
    - kubectl -n namespace delete configmap
    - kubectl -n namespace delete secrets
    - kubectl -n namespace delete pods
    - kubectl -n namespace delete deployment
    - kubectl -n namespace delete statefulset
    - kubectl -n namespace delete daemonset
    - kubectl -n namespace delete service
    - kubectl -n namespace delete ingress
    - kubectl -n namespace delete netpol
  - kubectl -n namespace edit: Eliminar recursos
    - kubectl -n namespace edit namespace
    - kubectl -n namespace edit configmap
    - kubectl -n namespace edit secrets
    - kubectl -n namespace edit pods
    - kubectl -n namespace edit deployment
    - kubectl -n namespace edit statefulset
    - kubectl -n namespace edit daemonset
    - kubectl -n namespace edit service
    - kubectl -n namespace edit ingress
    - kubectl -n namespace edit netpol
  - kubectl -n namespace rollout: mostrar actualización de recurso
  - kubectl -n namespace rollback: revertir actualización de recurso
  - kubectl -n namespace logs -f pod: mostrar logs
  - kubectl -n namespace exec -it pod bash: conectarse a un pod para correr comandos
  - kubectl -n namespace cp pod:/tmp/file ./file: copiar archivo de contenedor a local

## Helm
- Para qué sirve
- Tutorial
  - https://www.digitalocean.com/community/tutorials/how-to-install-software-on-kubernetes-clusters-with-the-helm-3-package-manager 
- Helmfile
  - https://github.com/roboll/helmfile 

# CI/CD
## General
- https://www.redhat.com/es/topics/devops/what-is-ci-cd 
- https://platform9.com/blog/kubernetes-ci-cd-pipelines-at-scale/ 

## Jenkins
- Como instalar con docker
  - https://github.com/inetshell/jenkins-server 
- Tutorial
  - https://www.tutorialspoint.com/jenkins/jenkins_quick_guide.htm 
- Como hacer pipelines
  - Freestyle
  - Groovy

# Desarrollo de software
## Python
- Tutorial
  - https://doc.lagout.org/programmation/python/Head%20First%20Python%2C%20First%20Edition%20%282010%29.pdf 
- Flask
  - https://www.digitalocean.com/community/tutorials/how-to-build-and-deploy-a-flask-application-using-docker-on-ubuntu-18-04 
- Django
  - https://docs.docker.com/samples/django/ 
- Boto3
  - https://boto3.amazonaws.com/v1/documentation/api/latest/index.html?id=docs_gateway 
  - https://boto3.amazonaws.com/v1/documentation/api/latest/guide/ec2-examples.html 

## Bash
- Guia rápida
  - https://linuxconfig.org/bash-scripting-tutorial 
- Debugging
  - set -x
- secuencia de control if
  - https://tldp.org/LDP/Bash-Beginners-Guide/html/sect_07_01.html

## Versión Control
- Git
  - Que es
    - https://openwebinars.net/blog/que-es-git-y-para-que-sirve/ 
  - Conceptos básicos
    - commit
    - pull request
    - merge
    - branch
    - rebase
  - Comandos básicos
    - git clone
    - git checkout
    - git diff
    - git add
    - git rm
    - git pull
    - git push
    - git commit
    - git merge
    - git log
    - git status
    - git cherry-pick
      - https://www.atlassian.com/es/git/tutorials/cherry-pick 
  - Para qué sirve el .gitignore
  - Resolución de conflictos
    - https://styde.net/ramas-y-resolucion-de-conflictos-en-git/

# Webservers
## Conceptos
- Códigos de retorno HTTP
  - 200: OK
  - 301: Permanent redirect
  - 302: Temporary redirect
  - 401: Unauthorized
  - 403: Forbidden
  - 404: Not found
  - 502: Bad gateway
  - 503: Service unavailable
- Referencia
  - https://www.restapitutorial.com/httpstatuscodes.html 
- Métodos:
  - GET
  - POST
  - HEAD
  - PUT
  - DELETE
- Referencia:
  - https://developer.mozilla.org/es/docs/Web/HTTP/Methods

## NGINX
- Configuración básica
  - https://www.digitalocean.com/community/tutorials/nginx-essentials-installation-and-configuration-troubleshooting 
- proxy_pass
  - https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/ 
- Comandos básicos
  - nginx -t
  - nginx -T
  - nginx -s reload

## HAProxy
- Tutorial
  - https://www.digitalocean.com/community/tutorials/an-introduction-to-haproxy-and-load-balancing-concepts 

## Apache
- Tutorial
  - https://www.digitalocean.com/community/tutorials/como-instalar-el-servidor-web-apache-en-ubuntu-18-04-es

## IIS
- Tutorial
  - https://techexpert.tips/es/windows-es/instalacion-de-iis-en-windows/ 

# Monitoreo
## ELK
- Tutorial
  - https://logz.io/learn/complete-guide-elk-stack/#intro 
- Tutorial docker
  - https://elk-docker.readthedocs.io/ 
- Componentes
  - Filebeat
  - Logstash
  - Elasticsearch
  - Kibana
- Elastic APM
  - https://www.elastic.co/es/apm 

# Bases de datos
## MySQL
- Tutorial de instalación
  - https://www.digitalocean.com/community/tutorials/how-to-install-mysql-on-ubuntu-20-04
  - https://wiki.inetshell.mx/index.php/MySQL 
- Comandos básicos
  - Como conectarse
  - Crear base de datos
  - Crear usuario
  - Asignar permisos
  - Cambiar password a usuario
  - Listar bases de datos
  - Respaldar base de datos
  - Restaurar base de datos

## PostgreSQL
- Tutorial de instalación
  - https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-on-ubuntu-20-04 
  - https://wiki.inetshell.mx/index.php/MySQL 
- Comandos básicos
  - Como conectarse
  - Crear base de datos
  - Crear usuario
  - Asignar permisos
  - Cambiar password a usuario
  - Listar bases de datos
  - Respaldar base de datos
  - Restaurar base de datos

## Clientes
- DBeaver
  - https://dbeaver.io/ 

# Sistemas Operativos
## Linux
- Debian/Ubuntu Linux
  - Como configurar interfaces de red
    - Bonding
      - https://securityhacklabs.net/articulo/networking-union-bonding-de-interfaces-de-red-en-gnu-linux
  - Agregar repositorios APT
  - Instalar paquetes con APT
- RedHat/CentOS Linux
  - Como configurar interfaces de red
    - Bonding
      - https://www.unixmen.com/linux-basics-create-network-bonding-on-centos-76-5/ 
    - nmtui
  - Agregar repositorios YUM
  - Instalar paquetes con YUM
  - yum whatprovides
- Fedora Linux
  - DNF
    - https://geekflare.com/es/dnf-intro/ 
  - Configuración de DNS
    - /etc/hosts
    - /etc/resolv.conf
- Administrar servicios con systemctl
  - systemctl status service
  - systemctl start service
  - systemctl restart service
  - systemctl stop service
  - systemctl enable service
  - systemctl disable service
- Administración de usuarios y grupos
  - Archivos importantes
    - /etc/passwd
    - /etc/shadow
    - /etc/group
  - passwd
  - adduser
  - usermod
  - addgroup
  - who
  - last
  - lastlog
- Configurar SELinux
- Configurar parámetros del kernel
  - sysctl
  - ulimits
- Editor vim
  - https://openwebinars.net/blog/vim-manual-de-uso-basico/ 
- Expresiones regulares (regex)
  - https://medium.com/factory-mind/regex-tutorial-a-simple-cheatsheet-by-examples-649dc1c3f285 
- Runlevels
  - https://www.liquidweb.com/kb/linux-runlevels-explained/
- Dispositivos especiales
  - /dev/stdin
  - /dev/stdout
  - /dev/stderr
  - /dev/zero
  - /dev/null
  - /dev/random
  - /dev/urandom
  - /dev/disk/
- Manejo de permisos
  - chown
  - chmod
  - chgrp
  - setfacl
  - getfacl
- Manipulación de texto
  - grep
  - sed
  - awk
  - cut
  - sort
  - uniq
- Manejo de archivo
  - rsync
  - md5sum
  - sha1sum
  - sha256sum
  - file
  - ln
  - ls
  - pwd
  - du
- Manejo de procesos
  - ps -aux
  - fg
  - bg
  - ctrl-z
  - jobs
  - disown
  - nohup
  - uptime
  - top
- Manejo de red
  - tcpdump
  - ping
  - traceroute
  - nslookup
  - curl
  - wget
  - ip a / ifconfig
  - ip r / route
  - ss / netstat 
- Manejo de dispositivos de almacenamiento
  - lsblk
  - blkid
  - dd
  - fdisk
  - parted
  - mkfs
  - fsck
  - mount
  - df
- Manejo de LVM
  - https://www.mikroways.net/2010/06/16/lvm-crear-y-expandir-volumenes/ 
- Debugging
  - lsof
  - strace
- Servicios básicos
  - BIND
  - SAMBA
  - Apache
  - NGINX

## Windows
- Como configurar interfaces de red
  - Agregar rutas estáticas
  - Configuración de firewall
- Manejo de discos
  - Administrador de discos
  - Comandos
    - diskpart
    - chkdsk
  - Expandir particiones
- Administración de usuarios y grupos
- Administración de permisos
  - Permisos NTFS
  - icacls
- Roles
  - Servidor de archivos
  - AD
  - DNS
- Manejo de paquetes
  - Chocolatey

## Autenticación
- LDAP
- Kerberos
- Active Directory
- Keycloak
- Okta
- SAML

# Virtualización
## Conceptos
- Discos virtuales
- Hipervisores
  - Hyper-V
  - KMV
  - ProxMox
  - ESX
  - VirtualBox
- Migración entre hipervisores

# Networking
## SSH
- Como se usa
  - https://raiolanetworks.es/blog/ssh/
- Como generar llaves SSH
- Como usar el archivo de configuración
- Como desactivar acceso por password
- Como hacer redirección de puertos
- Como usarlo como proxy

## VPN
- IPsec
- OpenVPN

## DNS
- Saber que es un FQDN (Full Qualified Domain Name)
  - https://1.bp.blogspot.com/-X9hb_bIgTMc/Wj-3XA53XBI/AAAAAAAACEo/891Kn23ZtisLzZVF7hD7BJVOjiuJuDj_wCLcBGAs/s1600/FQDN.png
- Saber los tipos de registros DNS más comunes
  - A (Address): FQDN -> IPv4
  - A (Address IPv6): FQDN -> IPv6
  - CNAME (Common Name): FQDN -> FQDN
  - NS (Name Server): Servidor DNS que atiende un dominio
  - PTR (Pointer): IP -> FQDN; Muy usado en SMTP/Mail server
  - MX (Main Exchange): IP mail server
  - TXT (Text): información en texto, se usa mucho para validar propiedad de dominios
  - CAA (Certification Authority Authorization): Se usa para definir generación de certificados
- Saber como se hace una delegación de DNS (Subdominio)
  - https://techclub.tajamar.es/delegacion-de-zona/ 
- Saber que puerto usa
  - 53/UDP para consultas cortas
  - 53/TCP para consultas de mas de 512 Bytes

## Puertos de servicios comunes
- SSH: 22/TCP
- DNS: 53/UDP, 53/TCP
- LDAP: 389/TCP
- LDAPS: 636/TCP
- SMTP: 25,587,436/TCP
- Syslog: 512/UDP
- HTTP: 80/TCP
- HTTPS: 443/TCP
- FTP: 21/TCP
- Telnet: 23/TCP
- DHCP: 67,68/UDP
- TFTP: 69/TCP
- POP3: 110/TCP
- POP3S: 993/TCP
- IMAP: 143/TCP
- IMAPS: 995/TCP
- SNMP: 161,162/UDP
- RDP: 3389/TCP
