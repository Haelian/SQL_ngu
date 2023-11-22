import streamlit as st
import numpy as np
import pandas as pd
import pickle
safeword = ["any","all","having","in","like","set","or","and","asc",
            "desc","order by","group by","join","union","insert","rename",
            "update","union","set","alter","database","information_schema","load_file","select"]

harm =["call","shutdown","version","drop","delete","check",
       "tuncat","concat","convert","deny","create","revoke","clear",
       "as","alter","cmdshell","system","sleep","waitfor",
       "DEC","BASE64","UNHEX","HEX","BIN","ASCII","Char","EXEC"]  #  bypass detection techniques with the help of signatures like

operator =["%","+","-","*","/","&","|","^","=",">","<","<=",">=",
          "<>","+=","-=","*=","/=","%=","&=","^-=","|*=",
          "all","and","any","between","exists","in","like","not","and","or","some"]

logical_operator=["all","and","any","between","exists","in","like","not","and","or","some"]

network_cmds=["sleep","waitfor","local_tcp_port","session","instance","session_id",
              "connect_time","net_transport" ,"num_reads","num_writes","client_net_address"] 

language_cmds=["create","rename", "alter", "drop","truncate","comment","select",
               "insert","update","delete","lock","call","explain plan","grant","revoke","commit","rollback","savepoint","set transaction"]
               
# "SERVERPROPERTY('productversion')", "SERVERPROPERTY ('productlevel')", "SERVERPROPERTY ('edition')"
database_info=["@@VERSION","SERVERPROPERTY","mds.mdm.tblSystem"]

no_roles =["admin","user"]


def cntofchar(sentence, word):
    to_find=word.upper()
    sent=sentence.upper()
    counter=sent.count(to_find)
    return counter

null =["null"]

hexadecimel =["0x0","0x1","0x2","0x3","0x4","0x5","0x6","0x7","0x8","0x9","0xA","0xB","0xC","0xD","0xE","0xF"]


alphabets = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
            'm', 'n','o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

digits =["0","1","2","3","4","5","6","7","8","9"]

spl_char =["\0","\'",'\"',"\b","\n","\r","\t","\Z","\\","\%","\_"]

singlequot =["'"]

doublequot =['"']

singlecmt =["-- "]

multicmt=["/*","*/"]

percentage=["%"]

punctuations=[".",",","?","[","]","{","}","-","(",")","...","'",":",";",'"',"!"]



def no_space(s):
 a_string = s
 word_list = a_string.split()
 return len(word_list)

def no_of_punctuations(s):
  cnt=0
  length=len(punctuations)
  for i in range(length):
    cnt+=cntofchar(s,punctuations[i])
  return cnt

def no_of_database_info(s):
  cnt=0
  length=len(database_info)
  for i in range(length):
    cnt+=cntofchar(s,database_info[i])
  return cnt

def no_of_language_cmds(s):
  cnt=0
  length=len(language_cmds)
  for i in range(length):
    cnt+=cntofchar(s,language_cmds[i])
  return cnt

def no_of_network_cmds(s):
  cnt=0
  length=len(network_cmds)
  for i in range(length):
    cnt+=cntofchar(s,network_cmds[i])
  return cnt

def no_of_multicmt(s):
  cnt=0
  length=len(multicmt)
  for i in range(length):
    cnt+=cntofchar(s,multicmt[i])
  return cnt

def no_of_singlecmt(s):
  cnt=0
  length=len(singlecmt)
  for i in range(length):
    cnt+=cntofchar(s,singlecmt[i])
  return cnt

def no_of_percentage(s):
  cnt=0
  length=len(percentage)
  for i in range(length):
    cnt+=cntofchar(s,percentage[i])
  return cnt

def no_logical_operator(s):
  cnt=0
  length=len(logical_operator)
  for i in range(length):
   cnt+=cntofchar(s,logical_operator[i])
  return cnt 

def nosinglequts(s):
  cnt=0
  length=len(singlequot)
  for i in range(length):
   cnt+=cntofchar(s,singlequot[i])
  return cnt

def nodoublequts(s):
  cnt=0
  length=len(doublequot)
  for i in range(length):
   cnt+=cntofchar(s,doublequot[i])
  return cnt

def no_safeword(s):
  cnt=0
  length=len(safeword)
  for i in range(length):
   cnt+=cntofchar(s,safeword[i])
  return cnt

def no_harm(s):
  cnt=0
  length=len(harm)
  for i in range(length):
   cnt+=cntofchar(s,harm[i])
  return cnt

def no_operator(s):
  cnt=0
  length=len(operator)
  for i in range(length):
   cnt+=cntofchar(s,operator[i])
  return cnt 

def no_null(s):
  cnt=0
  length=len(null)
  for i in range(length):
   cnt+=cntofchar(s,null[i])
  return cnt

def no_alphabets(s):
  cnt=0
  length=len(alphabets)
  for i in range(length):
   cnt+=cntofchar(s,alphabets[i])
  return cnt

def no_hexadecimels(s):
  cnt=0
  length=len(hexadecimel)
  for i in range(length):
   cnt+=cntofchar(s,hexadecimel[i])
  return cnt

def no_of_roles(s):
  cnt=0
  length=len(no_roles)
  for i in range(length):
   cnt+=cntofchar(s,no_roles[i])
  return cnt

def no_spl_char(s):
  cnt=0
  length=len(spl_char)
  for i in range(length):
   cnt+=cntofchar(s,spl_char[i])
  return cnt

def no_digits(s):
  cnt=0
  length=len(digits)
  for i in range(length):
   cnt+=cntofchar(s,digits[i])
  return cnt

#Function to extract features
def featureExtraction(s):

  features = []
  #Address bar based features (10)
  features.append(nosinglequts(s))
  features.append(nodoublequts(s))
  features.append(no_of_punctuations(s))
  features.append(no_of_singlecmt(s))
  features.append(no_of_multicmt(s))
  features.append(no_space(s))
  features.append(no_safeword(s))
  features.append(no_harm(s))
  features.append(no_of_percentage(s))
  features.append(no_logical_operator(s))
  features.append(no_operator(s))
  features.append(no_null(s))
  features.append(no_hexadecimels(s))
  features.append(no_of_database_info(s))
  features.append(no_of_roles(s))
  features.append(no_of_network_cmds(s))
  features.append(no_of_language_cmds(s))
  features.append(no_alphabets(s))
  features.append(no_digits(s))
  features.append(no_spl_char(s))
  
  return features
def sqli(s):
    feature=[]
    feature.append(featureExtraction(s))
    feature_names = ['Singlequotes', 'Doublequotes', 'Punctuations','1-linecmt',  'Mulline-cmt',  'Spaces','Safekywrd',
    'Harmflkywrd','Percentages','Log_oprtr',
    'Operator','Nulls','Hex-dec','Db_info',
    'Roles','Ntwr_cmds','Lang_cmds','Alphabets','Digits','Spl_char']
    plain = pd.DataFrame(feature, columns= feature_names)
    load_model = pickle.load(open(svm.pkl', 'rb'))
    # Apply model to make predictions
    prediction = load_model.predict(plain)
    #prediction_proba = load_model.predict_proba(X)
    return prediction


st.title('LOGIN')
username = st.text_input('Username')
password = st.text_input('Password', type='password')
if st.button('Login'):
    predict=sqli(username)
    if predict==1:
        st.warning('Day la SQLi', icon="⚠️")


