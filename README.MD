# Project 4: Item Catalog Application Project
### by Jaime Banda

This is the fourth project of the [Udacity Full-Stack Nanodegree - Build an Item Catalog Application Project,
Nanodegree](https://classroom.udacity.com/nanodegrees/nd004/parts/8d3e23e1-9ab6-47eb-b4f3-d5dc7ef27bf0/modules/348776022975462/lessons/3487760229239847/concepts/36269487530923).

## What it is and does

This is an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

Here are some URLs structures that the application follow to manage the catalog:

1. Th homepage displays all current categories along with the latest added items.

```
GET - http://localhost:5000/
```

2. Selecting a specific category shows you all the items available for that category.

```
GET - http://localhost:5000/products/Autos
GET - http://localhost:5000/products/Clothing
GET - http://localhost:5000/products/Electronic
GET - http://localhost:5000/products/Furniture
GET - http://localhost:5000/products/Grocery
GET -http://localhost:5000/products/Pharmacy
GET -http://localhost:5000/products/Toys
GET -http://localhost:5000/products/Wines
```

3. Selecting a specific item shows you specific information of that item.

```
GET - http://localhost:5000/product/{ITEM-SLUG}
```

4. After logging in, a user has the ability to add, update, or delete item info.

```
GET - http://localhost:5000/product/{ITEM-SLUG}
POST - http://localhost:5000/product/new/
POST - http://localhost:5000/product/{ITEM-SLUG}/edit/
POST - http://localhost:5000/product/{ITEM-SLUG}/delete/
```

5. The application provides a JSON endpoint to get the full catalog and an item of the catalog.

```
GET - http://localhost:5000/products/JSON
GET - http://localhost:5000/product/{ITEM-SLUG}/JSON
```

## Required Libraries and Dependencies

Python 2.x is required to run this project. The Python executable should be in
your default path, which the Python installer should have set.

You also need the following libraries to be downloaded from the internet

```
sudo pip install Werkzeug
sudo pip install python-slugify
```

## Project contents

This project consists for the following files:

* application.py - main Python script to run.
* db.py - Python database model.
* catalog.db - SQlite database (already filled with data).
* client_secrets.json - Google web clientID for OAuth.
* /static - Folder with CSS files, Javascript files and images for the project.
* /templates - HTML pages of the project.

## How to Run Project

You'll use a virtual machine (VM) to run an SQL database server and a web app that uses it. The VM is a Linux server system that runs on top of your own computer. You can share files easily between your computer and the VM.

### Install Vagrant
Vagrant is the software that configures the VM and lets you share files between your host computer and the VM's filesystem. Download it from [vagrantup.com](https://www.vagrantup.com/downloads.html). Install the version for your operating system.

### Download the VM configuration

There are a couple of different ways you can download the VM configuration. 

You can download and unzip this file: [FSND-Virtual-Machine.zip](https://d17h27t6h515a5.cloudfront.net/topher/2017/August/59822701_fsnd-virtual-machine/fsnd-virtual-machine.zip) This will give you a directory called FSND-Virtual-Machine. It may be located inside your Downloads folder.

Alternately, you can use Github to fork and clone the repository [https://github.com/udacity/fullstack-nanodegree-vm](https://github.com/udacity/fullstack-nanodegree-vm).

Either way, you will end up with a new directory containing the VM files. Change to this directory in your terminal with ```cd```. Inside, you will find another directory called vagrant. Change directory to the vagrant directory:

### Start the virtual machine

From your terminal, inside the vagrant subdirectory, run the command vagrant up. This will cause Vagrant to download the Linux operating system and install it. This may take quite a while (many minutes) depending on how fast your Internet connection is.

When vagrant up is finished running, you will get your shell prompt back. At this point, you can run ```vagrant ssh``` to log in to your newly installed Linux VM!

### Download the project zip file

Download the project zip file to you computer and unzip the file. Or clone this
repository to your desktop.

The files need to be in the vagrant subdirectory on your computer (where you started Vagrant from). Any file you create in one will be automatically shared to the other. This means that you can edit code in your favorite text editor, and run it inside the VM.

Files in the VM's /vagrant directory are shared with the vagrant folder on your computer. But other data inside the VM is not. For instance, the PostgreSQL database itself lives only inside the VM.


Navigate to the project directory and type in the following command:

```bash
python application.py
```

