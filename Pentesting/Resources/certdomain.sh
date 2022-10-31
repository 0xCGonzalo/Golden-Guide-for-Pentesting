#!/bin/bash
echo -e "               _      _                       _       "
echo -e "  ___ ___ _ __| |_ __| | ___  _ __ ___   __ _(_)_ __  "
echo -e " / __/ _ \ |__| __/ _| |/ _ \| |_ | _ \ / _| | | |_ \ "
echo -e "| (_|  __/ |  | || (_| | (_) | | | | | | (_| | | | | |"
echo -e " \___\___|_|   \__\____|\___/|_| |_| |_|\____|_|_| |_|"
echo -e "                                                      "

script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

read -p "Insert domain: " domain

echo -e ""
echo -e "Take a coffee!"
echo -e ""

curl https://crt.sh/?q=$domain -silent > domtest.txt

cat domtest.txt | egrep -i "*\.$domain" > domtest2.txt

sed 's/<TD>//g' domtest2.txt > domtest3.txt

sed 's/<\/TD>//g' domtest3.txt > domtest4.txt

sed s/[[:space:]]//g domtest4.txt > domtest5.txt

cat domtest5.txt | egrep -i "[-a-zA-Z0-9:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()%_\+.~#?&//=]*)" > domtest6.txt

sed 's/<BR>/\n/g' domtest6.txt | sort -u > domtest7.txt

cat domtest7.txt | egrep -i "^()?[a-z0-9]+([-.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$" > sub_ok_certdomain.txt

rm domtest*

cat sub_ok_certdomain.txt

echo -e ""

echo -e "Results save on $script_dir/sub_ok_certdomain.txt"
