#include <vector>
#include <unistd.h>
#include <ctime>
#include <cstring>
#include <cmath>
#include <fstream>
#include <ctime>

#include <stdexcept>

#include "seal.h"

//#include "enc_labels.h"

#ifndef CLEAR

#define CLEAR "clear"

#endif

//binary size of label
#define SIZE_LABEL 3

//upper bound on the values associated with each label
#define BOUND_VALUE 50

//number of users
#define NB_USERS 3

//base for encoding
#define BASE 3

using namespace std;
using namespace seal;


void dispTab(int tab[], int len) {
  cout << "[";

  for (int i=0; i<len; i++) {
    cout << tab[i] << ((i == len - 1) ? "" : ",");
  }
  cout << "]" << endl;
}


// Timer function
void dispTime(clock_t cBeginning) {
  // Displays the elapsed time between cBeginning and the current time
  cout << "Time : " << (clock() - cBeginning) / ((double) CLOCKS_PER_SEC) << " seconds." << endl << endl;
}


ChooserPoly copyPoly(ChooserPoly poly){
  ChooserPoly P(poly);
  return P;
}

void print_example_banner(string title)
{
  if (!title.empty())
    {
      size_t title_length = title.length();
      size_t banner_length = title_length + 2 + 2 * 10;
      string banner_top(banner_length, '*');
      string banner_middle = string(10, '*') + " " + title + " " + string(10, '*');

      cout << endl
	   << banner_top << endl
	   << banner_middle << endl
	   << banner_top << endl
	   << endl;
    }
}



// THis fucntion returns a sommation of all the values related to a label passed as parameter
BigPolyArray stat2 (vector< vector < BigPolyArray > > &users, Evaluator &evaluator, unsigned int label){
	
	BigPolyArray tmp;
	
	// We calculate the binary representation of the label
	//users.size --> NB_USERS ?
	for (size_t i=0; i < users.size(); ++i){
		if (i==0) tmp = users.at(i).at(label);
		else 
		{
			tmp = evaluator.add(tmp, users.at(i).at(label)); 
		}
	}
	// We return the sum of all the values of tmp_values
	return tmp;
}

void custom_parameters(EncryptionParameters &parms, int size_label, int nb_users, int bound_value, int base){
  //cout << "Custom parameters" << endl;
  clock_t start_custom = clock();

  //if pour le cas default sans parametre ? Mais constructeur a l'initialisation...
  ChooserEncoder encoder(base);

  ChooserEncryptor encryptor;
  ChooserEvaluator evaluator;

  //size of one coeff in the chosen basis
  ChooserPoly result;

  //value associated with each label
  ChooserPoly value(ceil(log(bound_value)/log(base)) + 1, base);//ou different second terme ??


  /* We don't need to consider the labels for the computation since they are not encrypted.
     We just access the label we want for each user and then add all the data.
     -> Sum of nb_users terms 
  */

  result = copyPoly(encryptor.encrypt(value));
  ChooserPoly cp = copyPoly(encryptor.encrypt(value));

  //cout << "add copies" << endl;

  for (int i = 1; i < (nb_users<<1); i++){
    result = evaluator.add(cp, result);
    }

  cout << endl << "Time spent simulating computation : " << endl;
  dispTime(start_custom);
  clock_t start_select = clock();

  bool select_ok = evaluator.select_parameters(result, parms);


  if ( !select_ok){
    cout << endl << "Time spent by the library to select accurate parameters : " << endl;
    dispTime(start_select);

    cout << endl << "Couldn't find appropriate encryption parameters for the given computation." << endl;
    cout << "Exiting..." << endl << endl;
    exit(1);
  }
  cout << endl << "Time spent by the library to select accurate parameters : " << endl;
  dispTime(start_select);
  
}



int main(int argc, char *argv[]){

  int size_label=SIZE_LABEL;
  int nb_users=NB_USERS;
  int bound_value = BOUND_VALUE;
  int base = BASE;

  if (argc == 1){
    cout << "DEFAULT PARAMETERS" << endl;
  }

 
  else if (argc == 5){
    cout << "USER PARAMETERS" << endl;
    nb_users = atoi(argv[1]);
    size_label = atoi(argv[2]);
    bound_value = atoi(argv[3]);
    base = atoi(argv[4]);
   
    if ( (base%2 == 0) || (base < 3) ){
      cout << "base must be an odd integer at least 3" << endl;
      return (1);
    }

  }

  else {
    print_example_banner("Usage : ");
    cout << "Default parameters : ./enc_labels.exe" << endl;
    cout << "User parameters : " << "./enc_labels.exe <nb_users> <size_label> <bound_value> <base>" << endl << endl;
    cout << " * nb_users : number of users" << endl;
    cout << " * size_label : number of bits used for each of the the labels" << endl;
    cout << " * bound_value : maximum value that can be paired with each of the labels" << endl;
    cout << " * base : base used for encoding integers into plaintext polynomials (must be an odd integer at least 3)" << endl;
    cout << endl;
    return(1);
  }

 
 

  print_example_banner("Simulation");

  cout << "Running test for " << nb_users << " users, " << size_label << " bits labels and values of max size " << bound_value << endl;
  cout << "Encoding is in base " << base << endl << endl;



  //Initialize parameters
  cout << "Initializing encryption parameters..." << endl;

  clock_t start = clock();

  //Encryption parameters
  EncryptionParameters parms;


  //Custom encryption parameters
  custom_parameters(parms, size_label, nb_users, bound_value, base);

  cout << "Total time for generating accurate parameters : " << endl;
  dispTime(start);

  cout << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
       << parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;
  cout << "Plain modulus : " << parms.plain_modulus().to_string() << endl << endl;

  //Encoder
  BalancedEncoder encoder(parms.plain_modulus(), base);

  // Timer
  clock_t beginning = clock();

  //Generate keys
  cout << "Generating keys..." << endl;
  KeyGenerator generator(parms);
  generator.generate();
  cout << "... key generation complete" << endl;
  BigPolyArray public_key = generator.public_key();
  BigPoly secret_key = generator.secret_key();

  cout << endl << "Key generation time :" << endl;
  dispTime(beginning);

  //Encryptor
  Encryptor encryptor(parms, public_key);

  //Evaluator
  Evaluator evaluator(parms);

  //Decryptor
  Decryptor decryptor(parms, secret_key);


  print_example_banner("Actual computation");

//Beginning of init params for test
  vector<vector<BigPolyArray> > dataBase;
  vector <BigPolyArray> user;

  
  clock_t start_database = clock();

  srand(time(NULL));

  cout << "Generating a random " << nb_users << " users long database..." << endl;

  cout << "users list generation ... " << endl; 

  for (int i=0; i<nb_users; i++){
  	for (int j=0; j < (1 << size_label); j++){
  		user.push_back(encryptor.encrypt(encoder.encode(rand()%bound_value)));
  	}
  	dataBase.push_back(user);
  	user.clear();
  }
  cout << "...generation complete." << endl << endl;;
  cout << "Time for generating database : " << endl;
  dispTime(start_database);


  clock_t computation = clock();
  BigPolyArray stat_result = stat2(dataBase, evaluator, 5);

  cout << endl<< "label 5 : " << encoder.decode_int64(decryptor.decrypt(stat_result)) << endl;

  cout << endl << "Time spent on computation to find the data we want :" << endl;
  dispTime(computation);

  //Relevant ?? irl we wouldn't generate a database since it would already be there ?
  cout << endl << "Total time :" << endl;
  dispTime(start);
  return 0;
}
