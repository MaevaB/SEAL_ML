#! /bin/bash

if [ -z $1 ];
then
echo "Usage : ./launch_test.sh <output_file>"
exit;
fi;

file=$1.txt


if [ -e $file ];
then
file=$1_$$.txt
echo "renamed output file" $file
fi;


touch $file


index=0

for size_label in `seq 3 6`;
do
    for nb_users in `seq 2 10 102 `;
    do
	echo ""
	echo "Running test #" $index
	echo "size_label = " $size_label " nb_users = " $nb_users, "base = 3 and bound_value = 20";

	./enc_labels.exe $nb_users $size_label 20 3 >> $file
	index=$(( ind + 1 ))
    done;
done;

