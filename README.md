# NPNT-Module

Objective: To Design the NPNT Module. NPNT module had reduced security threats that drones can possess, as they come in all shapes and sizes ranging from Nano (up to 250 grams) to Large (> 150Kg).

# pip3 install -r requirements.txt
# sudo apt-get install libgeos-dev
# Static IP - sudo nano /etc/dhcpcd.conf

interface wlan0
static ip_address=192.168.x.10/24
static routers=192.168.x.1
static domain_name_servers = 192.168.x.1 8.8.8.8 zzzzzz:zzz:zz

# Autoboot - sudo nano /home/pi/.bashrc
         - python3 /home/pi/NPNT-U-2.0-RPi3/dist/RPi_server.py
         
# ------Obfuscate the File-------
pyarmor obfuscate RPi_server.py

# ------compiled Python File-----
import py_compile
py_compile.compile('RPi_server.py')

# ----Note----
*Clear all the Trash Files
*Put compiled file in dist folder
