import sys
import subprocess
import boto
from boto.s3.key import Key
import urllib2
import ssl
from bs4 import BeautifulSoup
import socket
import boto3
import keyring
import logging
import time
import os
import json
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

LOG_FILE='/var/log/r2d2.log'
logging.basicConfig(filename=LOG_FILE,level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d/%m/%Y %H:%M:%S')

class r2d2(object):
      r2list=[]
      apikeylist=[]
      errorlist=[]
      PA_TOKEN=""
      
      MY_KEY1=""
      MY_SECRET1=""
      BUCKET_NAME1=""

      MY_KEY=""
      MY_SECRET=""
      BUCKET_NAME=""
      SMTP_SERVER=""
      SMTP_PORT=""
      MAIL_FROM=""
      MAIL_TO=""
      PATH_TO_FW_LIST=""
      WORKING_DIRECTORY=""

      def loadsecrets(self):
          logging.info('Cargando entorno y keys')
          PATH_TO_JSON="/scripts/r2d2/shellvar.json"
          with open (PATH_TO_JSON) as data_file:
               data =json.load (data_file) 
          self.PA_TOKEN=data["PA_TOKEN"]
          self.MY_KEY=data["MY_KEY"]
          self.MY_SECRET=data["MY_SECRET"]
          self.BUCKET_NAME=data["BUCKET_NAME"] 
          self.SMTP_SERVER=data["SMTP_SERVER"]
          self.SMTP_PORT=data["SMTP_PORT"]
          self.MAIL_FROM=data["MAIL_FROM"] 
          self.MAIL_TO=data["MAIL_TO"]
          self.PATH_TO_FW_LIST=data["PATH_TO_FW_LIST"]
          self.WORKING_DIRECTORY=data["WORKING_DIRECTORY"]

      def loadlistfws(self):
            logging.info('Leyendo File de entrada fwlist.txt')  
            fwlist=open("/scripts/r2d2/fwlist.txt",'r')
            lineamela=""
            for line in fwlist:
                  lineamela=line.replace('\n', ' ')
                  if '[' in lineamela or '#' in lineamela:
                        continue
                  lineamela=lineamela.strip(' ')    
                  self.r2list.append(lineamela)
            print fwlist
            fwlist.close()

      def getconfig(self):
            for fw in self.r2list:
                  if not self.testconnection1(fw):
                        MESSAGE_TO_LOG="Error en la conexin al firewall {}".format(fw)
                        print MESSAGE_TO_LOG
                        logging.error(MESSAGE_TO_LOG)
                        self.errorlist.append(MESSAGE_TO_LOG)
			continue

                  print 'Bajando config ', fw
                  COMMAND_GET_CONFIG='curl --silent -k -H "Accept: application/xml" -H "Content-Type: application/xml" -X GET "https://{}/api/?type=export&category=configuration&key={}"'.format(fw,self.PA_TOKEN)
                  result=subprocess.check_output(COMMAND_GET_CONFIG,shell=True)
                  result1=result.split(' ')
                  if "<config" in result1[0]:
                        COMMAND_GET_CONFIG='curl --silent -o `date +%Y%m%d`-{}.xml  -k -H "Accept: application/xml" -H "Content-Type: application/xml" -X GET "https://{}/api/?type=export&category=configuration&key={}"'.format(fw,fw,self.PA_TOKEN)
                        result=subprocess.check_output(COMMAND_GET_CONFIG,shell=True)
                  else:
                        soup=BeautifulSoup(result,"html.parser")
                        for strong_tag in soup.find_all('msg'):
                              MESSAGE_TO_LOG="Error descargando la config del firewall {}".format(fw)
                              print MESSAGE_TO_LOG
                              self.errorlist.append(MESSAGE_TO_LOG) 
                              logging.error(MESSAGE_TO_LOG)
      
      def compressconfig(self):
            COMPRESS_FILES="tar -jcvf `date +%Y%m%d_%H.%M.%S`.tar.bz2 *.xml"
            logging.info("Comprimiendo Backups")
            result=subprocess.check_output(COMPRESS_FILES,shell=True)
            GET_LAST_FILE="ls -1t | head -n 1"
            result=subprocess.check_output(GET_LAST_FILE,shell=True)
            return result.replace('\n',"")
	
      def upandcleanconfig(self):
            FINDCOMPRESSIONFILES="find . -name '*.bz2' -cmin -2 | sort"
            result=subprocess.check_output(FINDCOMPRESSIONFILES,shell=True)
            print "result compression: ",result
            result=result.split('/')
            up=[line.replace('\n.','') for line in result if ".bz2" in line]
            CLEANCONFIGS="rm *.xml"
            result=subprocess.check_output(CLEANCONFIGS,shell=True)
            print 'name: ',up[-1]
            logging.info('Archivo a subir: {}'.format(up[-1]))
            self.uploadconfig(up[-1])

      def uploadconfig (self,filezip):
            ERASEBZ2="rm *.bz2"
            filezip=filezip.replace(" ","")
            filezip=filezip.replace("\n","")      
            boto3_connect=boto3.client('s3', aws_access_key_id=self.MY_KEY,aws_secret_access_key=self.MY_SECRET)
            boto3_connect.upload_file(filezip,self.BUCKET_NAME,filezip)
            time.sleep(10)
            self.cleanandleavethirty()
         
      def cleanandleavethirty (self):
            #LISTCLEANFILES='ls -tl {} --time-style=full-iso  | awk \'{print $9}\' | grep bz2'.format(self.WORKING_DIRECTORY)
            LISTCLEANFILES='ls -tl /scripts/r2d2/ --time-style=full-iso  | awk \'{print $9}\' | grep bz2'
            result=subprocess.check_output(LISTCLEANFILES,shell=True)
            result=result.split('\n')
            if len (result) > 30:
               for file in result[30:]:
                   if 'bz2' in file:
                       print 'Archivo a borrar: ', file 
                       BORRAR_FILE='rm {}/{}'.format(WORKING_DIRECTORY,file)
                       result=subprocess.check_output(BORRAR_FILE,shell=True) 	
                   

      def testconnection1(self,fwip):
            s=socket.socket()
            s.settimeout(3)
            try:
                  s.connect((fwip,443))
            except Exception, e:
                  return False
            else:
                  return True
            finally:
                  s.close()
      
      def check_and_send_errors(self):
          MAIL_BODY="Se detectaron los siguientes errores en la realizacion de los backups: \n\n\n"
          if self.errorlist:
             logging.info("Enviando mails con errores...")
             for error in self.errorlist:
                 MAIL_BODY+=error+'\n'
             print "BODY: {}".format(MAIL_BODY)
             self.send_mail(self.MAIL_FROM,self.MAIL_TO,'None','Error backups palo alto',MAIL_BODY,[],'localhost') 
    
      def send_mail (self,send_from=None, send_to=None, cc=None, subject='ERROR EN LOS BACKUPS PALO ALTO', text='Se registraron los siguientes errores', files=[], server="localhost"):
          destino = [send_to, cc]
          msg = MIMEMultipart()
          msg['From'] = send_from
          msg['To'] = send_to
          msg['cc'] = cc
          #msg['Date'] = formatdate(localtime=True)
          msg['Subject'] = subject
          #Con html...
          msg.attach( MIMEText(text,'plain') )
          smtp = smtplib.SMTP(self.SMTP_SERVER,int(self.SMTP_PORT))
          smtp.sendmail(send_from, destino, msg.as_string())
          logging.info("Mail Enviado.")
          smtp.close()

def main():
      robot=r2d2()
      robot.loadsecrets()
      robot.loadlistfws()
      robot.getconfig()
      print "Comprimiendo"
      filezip=robot.compressconfig()
      print "Subiendo a AWS"
      robot.upandcleanconfig()
      robot.check_and_send_errors()
      print "FIN"

main()
