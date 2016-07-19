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
double dispTime(clock_t cBeginning) {
  // Displays the elapsed time between cBeginning and the current time
  cout << "Time : " << (clock() - cBeginning) / ((double) CLOCKS_PER_SEC) << " seconds." << endl << endl;
  return (clock() - cBeginning) / ((double) CLOCKS_PER_SEC);
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

//On a construit une structure avant pour ne pas compter la generation des parametres dans le timer
BigPolyArray sum (int nb_users, vector<BigPolyArray> values, Evaluator &evaluator, int index_start, int index_end){
  if (index_start == index_end){
    return values.at(index_start);
  }
  else{
    int index_mid = floor( (index_start+index_end) / 2 );
    return evaluator.add( sum(nb_users, values, evaluator, index_start, index_mid), 
			  sum(nb_users, values, evaluator, index_mid + 1, index_end) );
  }

}

double average(int bound_value, int nb_users, int base, int nb_loop, Encryptor &encryptor, BalancedEncoder &encoder, Evaluator &evaluator, Decryptor &decryptor){
  vector<BigPolyArray> enc_table;


  cout << "Generating random database..." << endl;
  //table of the values from all the users
  vector<vector<BigPolyArray>> values;
  vector<BigPolyArray> elem;
  //generate a random table for all the users (new rand for each loop /!\)
  //Do not take too big nb_loop because table is size nb_loop * nb_users
  for (int j=0; j< nb_loop; j++){
    for ( int i=0; i < nb_users; i++){
      elem.push_back(encryptor.encrypt(encoder.encode(rand()%bound_value)));
    }
    values.push_back(elem);
    elem.clear();
  }
  
  cout << "done" << endl;

  clock_t start = clock();
  for ( int i=0; i < nb_loop; i++){

    enc_table.push_back( sum(nb_users, values.at(i), evaluator, 0, nb_users - 1));

  }
  cout << "Time for computing " << nb_loop << " sums of " << nb_users << " users :" << endl;
    double t = dispTime(start);
    
    t=t/nb_loop;
 
  return t;
}
ChooserPoly add_many(ChooserEvaluator &evaluator, ChooserPoly element, int index_start, int index_end) {
  if (index_end <= index_start) {
    return element;
  }
  else {
    int index_mid = floor( (index_start+index_end) / 2 );
    return evaluator.add(add_many(evaluator, element, index_start, index_mid),
                         add_many(evaluator, element, index_mid + 1, index_end));
  }
}

void custom_parameters(EncryptionParameters &parms, int nb_users, int bound_value, int base){
  //cout << "Custom parameters" << endl;
  clock_t start_custom = clock();

  //if pour le cas default sans parametre ? Mais constructeur a l'initialisation...
  ChooserEncoder encoder;
  //ChooserEncoder encoder(base);
  ChooserEncryptor encryptor;
  ChooserEvaluator evaluator;

  //size of one coeff in the chosen basis
  //size_coeff = (base - 1)/2;

  ChooserPoly result;

  //value associated with each label
  //ChooserPoly value(ceil(log(bound_value)/log(base)) + 1, 1);//ou different second terme ??
  ChooserPoly value = encryptor.encrypt(encoder.encode(bound_value));
  //ChooserPoly value = encryptor.encrypt(encoder.encode(0));

  /* We don't need to consider the labels for the computation since they are not encrypted.
     We just access the label we want for each user and then add all the data.
     -> Sum of nb_users terms 
  */

  result = copyPoly(value);
  ChooserPoly cp = copyPoly(value);

  //cout << "add copies" << endl;

  result = add_many(evaluator, value, 0, nb_users-1);

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

  int nb_users=NB_USERS;
  int bound_value = BOUND_VALUE;
  int base = BASE;

  if (argc == 1){
    cout << "DEFAULT PARAMETERS" << endl;
  }

 
  else if (argc == 4){
    cout << "USER PARAMETERS" << endl;
    nb_users = atoi(argv[1]);
    bound_value = atoi(argv[2]);
    base = atoi(argv[3]);
   
    if ( (base%2 == 0) || (base < 3) ){
      cout << "base must be an odd integer at least 3" << endl;
      return (1);
    }

  }

  else {
    print_example_banner("Usage : ");
    cout << "Default parameters : ./enc_labels.exe" << endl;
    cout << "User parameters : " << "./enc_labels.exe <nb_users> <bound_value> <base>" << endl << endl;
    cout << " * nb_users : number of users" << endl;
    cout << " * bound_value : maximum value that can be paired with each of the labels" << endl;
    cout << " * base : base used for encoding integers into plaintext polynomials (must be an odd integer at least 3)" << endl;
    cout << endl;
    return(1);
  }

 
 

  print_example_banner("Simulation");

  cout << "Running test for " << nb_users << " users, " << "and values of max size " << bound_value << endl;
  cout << "Encoding is in base " << base << endl << endl;



  //Initialize parameters
  cout << "Initializing encryption parameters..." << endl;

  clock_t start = clock();

  //Encryption parameters
  EncryptionParameters parms;


  //Custom encryption parameters
  custom_parameters(parms, nb_users, bound_value, base);

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


  srand(time(NULL));

 
  clock_t computation = clock();
  double result = average(bound_value, nb_users, base, 10, encryptor, encoder, evaluator, decryptor);

  cout << endl<< "Average computation time : " << result << endl;

  cout << endl << "computation time :" << endl;
  dispTime(computation);

  //Relevant ?? irl we wouldn't generate a database since it would already be there ?
  cout << endl << "Total time :" << endl;
  dispTime(start);
  return 0;
}

