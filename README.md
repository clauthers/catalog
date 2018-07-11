# Catalog App Descrption
This program is a web based Catalog app that gives authenicated users the ability to add, edit and delete items.  Unauthenicated users can view items.

# How to execute program
1. Dowanload and install VirtualBox version 5.1 (https://www.virtualbox.org/wiki/Download_Old_Builds_5_1)
2. Download and install Vagrant (https://www.vagrantup.com/downloads.html)
3. Configure the enviroment by cloning the following respository: https://github.com/udacity/fullstack-nanodegree-vm
4. Navigate to the catalog folder and place the contains of the zip file in that folder
5. Open a terminal window and navigate to the folder where vagrant file is located
6. Enter the command: vagrant up
7. Enter the command: vagrant ssh
8. Enter the command: cd /vagrant/catalog
9. Enter the command: python database_setup.py
10. Enter the command: python lotsofcatalogs.py
11. Enter the command: python catalog.py
12. open a web browser and go to the URL: http://localhost:8000/