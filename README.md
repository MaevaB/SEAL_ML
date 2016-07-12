# SEAL_ML

To launch the test for parameters selection : 

>./distribution

(Default parameters)

or 

>./distribution *nb_user size_label bound_value base*

* nb_users : number of users
* size_label : number of bits used for each of the the labels
* bound_value : maximum value that can be paired with each of the labels
* base : base used for encoding integers into plaintext polynomials (must be an odd integer at least 3)



To launch the whole test : 

>./enc_labels

(Default parameters)

or

>./enc_labels *nb_user size_label bound_value base*
