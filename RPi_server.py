#!/usr/bin/python3
import glob
from getmac import get_mac_address
import threading
import datetime
import socket
import xml.etree.ElementTree as et
import serial
from shapely.geometry import Point
from shapely.geometry import Polygon
import unittest
import cryptography
import signxml as sx
from lxml import etree
import time as t
from dronekit import connect, LocationGlobalRelative,VehicleMode
from pymavlink import mavutil
import future
import argparse
import json
import os
import RPi.GPIO as GPIO
from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
import base64
from smbus import SMBus
addr = 0x8
bus = SMBus(1)
data = 11
data1 = 21
data2 = 31


class RPi_server(unittest.TestCase):
    global current_location
    global tree
    global lati
    global longi
    ret=None
    seti=None
    reti=None
    rtl_mode=None
    channel=21
    etime=None
    signed_pa=r'permission_artifact1.xml'
    cert=r'/home/pi/NPNT-U-2.0-RPi3/dgca.cert'
    vehicle=None
    time_comp=None
    geofence=[]
    latitude=None
    longitude=None
    p_exit=None
    gps_status=None
    def gps_connection(self):
        try:
            print('In GPS')
            gps1=serial.Serial('/dev/ttyUSB0',baudrate=9600)
            if gps1.isOpen():
                print('gps:True')
            while gps1.isOpen():
                line = str(gps1.readline())
                print(line)
                data = line.split(",")
                if data[0] == "b'$GPRMC" or data[0]=="b'$GNRMC":
                    if data[2] == "A":
                        lat = data[3]
                        long = data[5]
                        dd = int(float(lat) / 100)
                        ss = float(lat) - (dd * 100)
                        xxx = dd + ss / 60
                        self.latitude=xxx
                        ddd = int(float(long) / 100)
                        sss = float(long) - (ddd * 100)
                        yyy = ddd + sss / 60
                        self.longitude=yyy
                        print(xxx,yyy)
                if self.latitude is not None:
                    break
                if self.p_exit==True:
                    print('gps close')
                    break
            gps1.close()
        except:
            self.gps_status=True
            print('GPS Problem')


    def vehicle_init(self):
        self.vehicle = connect('/dev/ttyS0',baud=921600, wait_ready=False)
        print(self.vehicle.version)
        print(self.vehicle._vehicle_type,self.vehicle.armed,sep='\n')
        print(self.vehicle.location.global_frame.lat)
        print(self.vehicle.location.global_frame.lon)


        self.vehicle.armed=False

    def check_time_in_PA(self,sc):
        now = datetime.datetime.now()
        print(now)
        global start_time
        global end_time

        self.tree = et.parse("permission_artifact1.xml")
        for node in self.tree.iter("FlightParameters"):
            start_time = node.attrib["flightStartTime"]
            end_time = node.attrib["flightEndTime"]
        sr = start_time.replace('T', ' ')
        er = end_time.replace('T', ' ')
        st = sr.replace('+05:30', '')
        ett = er.replace('+05:30', '')
        st_time = st.strip()
        ett_time = ett.strip()
        print(st, ett, sep='/')
        s_time = datetime.datetime.strptime(st_time, "%Y-%m-%d %H:%M:%S.%f")
        self.e_time = datetime.datetime.strptime(ett_time, "%Y-%m-%d %H:%M:%S.%f")
        if self.e_time >= now >= s_time:
            print("Time Test Passed")
            self.ret=True
            sc.send(b'timec')
        else:
            print("Time Test Fail")
            self.ret=False
            sc.send(b'timef')
        print(self.ret)
        return self.ret

    def geofence_area_check(self,sc):
        waypoints = []
        for node in self.tree.iter("Coordinate"):
            a = float(node.attrib['latitude'])
            b = float(node.attrib['longitude'])
            c = (a,b)
            waypoints.append(c)
        li=waypoints[:4]
        self.geofence=li
        i=1


        self.gps_connection()
        print('iNside')


        try:
            print(self.latitude,self.longitude)
            p1=Point(self.latitude,self.longitude)
            poly = Polygon(li)
            print(li)
            cond = poly.contains(p1)
            print("geofence ",cond)

            if cond == True or i==5:
                if cond==True:
                    print("Geofence area is right")
                    sc.send(b'Geofc')
                    self.reti=True

                else:
                    print("Your GPS is not fetching data")
                    sc.send(b'Geofn')
                    self.reti=False
            else:
                print("you are at wrong place")
                sc.send(b'Geoff')
                i=i+1
                self.reti=False
            print(self.reti)

            return self.reti
        except:
            sc.send(b'GPSPF')

    def check_geofence_breach(self,latitude,longitude):
        p1=Point(latitude,longitude)
        poly = Polygon(self.geofence)
        cond = poly.contains(p1)
        if cond is True:
            self.rtl_mode=True
        else:
            #print('You Breach the Geofence')
            self.rtl_mode=False
    def time_check(self):
        now = datetime.datetime.now()
        if now>=self.e_time:
            #print('flight time reached')
            self.time_comp=True
        else:
            self.time_comp=False

    def pa_verification(self,xml_file, certificate_path,sc):

        # TODO -  refactor such that this verifies for generic stuff
        tree = etree.parse(xml_file)
        root = tree.getroot()
        with open(certificate_path) as f:
            certificate = f.read()

            try:
                verified_data = sx.XMLVerifier().verify(data=root, require_x509=True, x509_cert=certificate).signed_xml
                # The file signature is authentic
                print("Signature Verified")
                sc.send(b'SpuPA')
                self.seti=True

            except cryptography.exceptions.InvalidSignature:
                # print(verified_data)
                # add the type of exception
                print('Signature Not Verified')
                sc.send(b'SpuPf')
                self.seti=False

            finally:
                print(self.seti)

        return self.seti

    def sign_log(self,log_path, private_key_path, out_path=None):
        with open(log_path, "rb") as log_obj, open(private_key_path) as key_ob:
            jd = json.loads(log_obj.read())
            rsa_key = RSA.import_key(key_ob.read())
            hashed_logdata = SHA256.new(json.dumps((jd['FlightLog'])).encode())
            log_signature = pkcs1_15.new(rsa_key).sign(hashed_logdata)
            # the signature is encoded in base64 for transport
            enc = base64.b64encode(log_signature)
            # dealing with python's byte string expression
            jd['Signature'] = enc.decode('ascii')
        if out_path:
            save_path = out_path
        else:
            save_path = log_path[:-5] + ".json"
        with open(save_path, 'w') as outfile:
            json.dump(jd, outfile, indent=4)
        return save_path


    def create_log_file(self):
        global xxx
        global yyy
        ts = 0
        list_data=[]
        print('generating log file ...')
        i = datetime.date.today()
        ii=datetime.datetime.now()
        os.makedirs(os.path.dirname('/home/pi/Johnnette_Technologies/json_{}/'.format(i)),exist_ok=True)
        json_filee = open('/home/pi/Johnnette_Technologies/json_{}/json_file{}_{}.json'.format(i,ii.hour,ii.minute), 'w')
        print("File_name : ",json_filee)
        print('Waiting for Arming...')
        print('...')
        print('Arming status :',self.vehicle.armed)
        while self.vehicle.armed==False:
            if self.vehicle.armed==True:
                print('Armed')
                break
        print('Vehicle is Armed')
        while True:
            n = datetime.datetime.now()
            ts = int(datetime.datetime.timestamp(n))
            data = {'TimeStamp': ts,
                        'Longitude': self.vehicle.location.global_frame.lon,
                        'Latitude': self.vehicle.location.global_frame.lat,
                        'Altitude': self.vehicle.location.global_relative_frame.alt
                        }

            list_data.append(data)
            t.sleep(1)
            self.check_geofence_breach(self.vehicle.location.global_frame.lat,self.vehicle.location.global_frame.lon)
            self.time_check()
            while self.rtl_mode==False:
                self.vehicle.mode=VehicleMode("RTL")
                if self.vehicle.mode.name=='RTL':
                    break
            if self.vehicle.mode.name=='RTL' and self.rtl_mode==True:
                pass

            if self.time_comp==True:
                print('Activating RTL mode...')
                self.vehicle.mode=VehicleMode('RTL')
                t.sleep(15)
                while self.vehicle.mode=='RTL':
                    if self.vehicle.armed==False:
                        break
            if self.vehicle.armed==False:
                print('vehicle is disarmed')
                break
        flight_log={"PermissionArtefact":'',"FlightLog":list_data}
        json.dump(flight_log,json_filee,indent=2)
        json_filee.close()
        print('log file created successfully')
        print('signing the log file...')
        try:
            self.sign_log('/home/pi/Johnnette_Technologies/json_{}/json_file{}_{}.json'.format(i,ii.hour,ii.minute),'/home/pi/NPNT-U-2.0-RPi3/sample_key_private.pem')
            print('Signed successfull')

        except:
            print('There is no file in Directory to sign')


    def send_logfile(self,sc):
        list_of_filename=glob.glob('/home/pi/Johnnette_Technologies/*')
        latest_file=max(list_of_filename,key=os.path.getctime)
        print(latest_file)
        dir_log=latest_file+'/*'
        print(dir_log)
        list_of_log=glob.glob(dir_log)
        latest_file=max(list_of_log,key=os.path.getctime)
        print(latest_file)
        f=open(latest_file,'rb')

        read_file=f.read(1024)
        while read_file:
            sc.send(read_file)
            read_file=f.read(1024)
            if not read_file:
                sc.send(b'')
                t.sleep(2)
                break

        sc.send(b'END')
        f.close()
        print('send successfully')

    def receive_pa(self):

        #self.r_led.on()
        global s
        try:
            s = socket.socket()
            host=''
            s.bind((host, 1499))
            s.listen(5)

            # Accepts up to 10 connections.
            while True:
                self.gpiostp()
                GPIO.output(17, GPIO.HIGH)
                print('connecting...')
                sc, address = s.accept()
                print('connected with '+ address[0])
                print(address)
                op=sc.recv(9)
                op=op.decode('utf-8')
                print(op)
                while op=='Connected':
                    print('Connected Successfully')
                    opp=sc.recv(4)


                    if opp==b'down':
                        self.send_logfile(sc)
                    if opp==b'NPNT':
                        GPIO.output(27, GPIO.HIGH)
                        GPIO.output(17, GPIO.LOW)
                        print('NPNT receiving...')
                        i = 1
                        f = open('permission_artifact' + str(i)+".xml", 'wb')
                        i = i+1
                        while True:
                            # receive data and write it to file
                            l = sc.recv(1024)
                            if l==b'END':
                                print('Empty')
                                break

                            f.write(l)
                            print(l)

                        f.close()
                        print('connection closed')
                        #self.r_led.off()
                        #self.y_led.on()
                        self.check_time_in_PA(sc)
                        for i in range(0,2):
                            self.geofence_area_check(sc)
                        self.pa_verification(self.signed_pa,self.cert,sc)
                        if self.reti==True and self.ret is True and self.seti is True:
                            #self.y_led.off()
                            GPIO.output(27, GPIO.LOW)
                            GPIO.output(4, GPIO.HIGH)
                            sc.send(b'Valid')
                            #self.g_led.on()

                            GPIO.setup(22, GPIO.OUT)
                            GPIO.output(22, GPIO.LOW)
                            #relay = gpiozero.OutputDevice(self.relay_pin, active_high=False, initial_value=False)
                            bus.write_byte_data(addr, 0, data1)
                            self.vehicle_init()
                            print('all conditions are satisfied')
                            print('Powering pixhawk')
                            print('waiting for arming....')
                            self.create_log_file()
                            GPIO.output(17, GPIO.HIGH)
                            GPIO.output(4, GPIO.LOW)
                            #self.r_led.on()
                            #self.g_led.off()
                            self.vehicle.close()
                            bus.write_byte_data(addr, 0, data2)
                            #relay.on()
                            #self.r_led.off()
                            GPIO.cleanup()
                            self.p_exit=True

                        else:
                            print('PA is not valid')
                            sc.send(b'faill')
                            GPIO.output(27, GPIO.LOW)
                            GPIO.output(17, GPIO.HIGH)
                            #self.y_led.off()
                            #self.r_led.on()
                            self.p_exit=True
                        break
                sc.close()
            s.close()
        except Excecption as e:
            print('Connection Problem',e)
        print('socket close')

    def gpiostp(self):
        GPIO.cleanup()
        GPIO.setmode(GPIO.BCM)
        GPIO.setwarnings(False)
        GPIO.setup(17, GPIO.OUT)
        GPIO.setup(27, GPIO.OUT)
        GPIO.setup(4, GPIO.OUT)


r = RPi_server()
try:
     mac=get_mac_address(interface='wlan0')
except:
    mac="00:00:00:00:00:00"
print(mac)
bus.write_byte_data(addr, 0, data2)
if mac=='b8:27:eb:58:ea:2f':
    print('same config')
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(22, GPIO.OUT)
    GPIO.setwarnings(False)
    GPIO.cleanup()
    bus.write_byte_data(addr, 0, data) # line 1
    t.sleep(0.1)
    rc = bus.read_byte_data(addr, 0) # line 2
    print(rc)#200 receive then arduino ok
    if rc==200:
        print('Redundancy check : Checked ')
        r.receive_pa()
    else:
        print('Redundancy not ok',rc)
    print('server_off')
