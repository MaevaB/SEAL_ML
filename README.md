# SEAL_ML

Our goal is to simulate 2 models of encrypted data collection by a server. 

In the first model, each user has a set of data, and each data has a label associated to it.
Users encrypt their labels and data, and send each pair to the server if the data part is not zero.
Since the labels and data are encrypted, it doesn't leak information on which label have a zero value associated, even though it does allow the server to know how many zeros there are.
The server will have to compute the encrypted data he received. He will add the values of one specific label for all users.
And then send back the result to each user, who will be able to decrypt it.

In the second model (implementation still in progress), we do the exact same computation but without encrypting the labels.
Thus, we send only the encrypted data to the server and not the labels. The server is able to collect the data he needs using the indexes of each data.


Compile : 
>cd sealcrypto/distribution

>make


To launch the whole test for the first model : 
>cd sealcrypto/bin

>./enc_labels

(Default parameters)

or

>./enc_labels *nb_user size_label bound_value base*


* nb_users : number of users
* size_label : number of bits used for each of the the labels
* bound_value : maximum value that can be paired with each of the labels
* base : base used for encoding integers into plaintext polynomials (must be an odd integer at least 3)



To launch the test for parameters selection (first model) : 
>cd sealcrypto/bin

>./distribution

(Default parameters)

or 

>./distribution *nb_user size_label bound_value base*
