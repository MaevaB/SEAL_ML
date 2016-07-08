#include <vector>
#include <unistd.h>
#include <ctime>
#include <cstring>
#include <cmath>
#include <fstream>
#include <ctime>

#include <stdexcept>

#include "seal.h"

#ifndef CLEAR

#define CLEAR "clear"

#endif

//binary size of label
#define SIZE_LABEL 5

//upper bound on the values associated with each label
#define BOUND_VALUE 50

//number of users
#define NB_USERS 3

//base for encoding
#define BASE 3

using namespace std;
using namespace seal;

void print_example_banner(string title);
void dispTime(clock_t cBeginning);

void custom_parameters(EncryptionParameters &parms, int size_label, int nb_users, int bound_value, int base);
ChooserPoly get_label(ChooserEncoder &encoder, ChooserEncryptor &encryptor,ChooserEvaluator &evaluator, ChooserPoly elem_label, int index_start, int index_end);
ChooserPoly equals(ChooserEncoder &encoder, ChooserEvaluator &evaluator, ChooserPoly elem_label);
ChooserPoly copyPoly(ChooserPoly poly);

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
   
    if (base%2 == 0){
      cout << "base must be an odd integer at least 3" << endl;
      return (1);
    }

  }

  else {
    print_example_banner("Usage : ");
    cout << "Default parameters : ./distribution.exe" << endl;
    cout << "User parameters : " << "./distribution.exe <nb_users> <size_label> <bound_value> <base>" << endl << endl;
    cout << " * nb_users : number of users" << endl;
    cout << " * size_label : number of bits used for each of the the labels" << endl;
    cout << " * bound_value : maximum value that can be paired with each of the labels" << endl;
    cout << " * base : base used for encoding integers into plaintext polynomials (must be an odd integer at least 3)" << endl;
    cout << endl;
    return(1);
  }

 
 

  print_example_banner("Distribution");

  cout << "Running test for " << nb_users << " users, " << size_label << " bits labels and values of max size " << bound_value << endl;
  cout << "Encoding is in base " << base << endl << endl;

  //Initialize parameters
  cout << "Initializing encryption parameters..." << endl;

  clock_t start = clock();

  //Encryption parameters
  EncryptionParameters parms;


  //Custom encryption parameters
  custom_parameters(parms, size_label, nb_users, bound_value, base);

  cout << "Total time for generating accurate parameters : " << cout;
  dispTime(start);

  cout << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
       << parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;
  cout << "Plain modulus : " << parms.plain_modulus().to_string() << endl;


  //Encoder
  BalancedEncoder encoder(parms.plain_modulus());

  //Generate keys
  cout << "Generating keys..." << endl;
  KeyGenerator generator(parms);
  generator.generate();
  cout << "... key generation complete" << endl;
  BigPolyArray public_key = generator.public_key();
  BigPoly secret_key = generator.secret_key();

  //Encryptor
  Encryptor encryptor(parms, public_key);

  //Evaluator
  Evaluator evaluator(parms);

  //Decryptor
  Decryptor decryptor(parms, secret_key);


  return 0;
  }

void custom_parameters(EncryptionParameters &parms, int size_label, int nb_users, int bound_value, int base){
  //cout << "Custom parameters" << endl;
  clock_t start_custom = clock();

  //if pour le cas default sans parametre ? Mais constructeur a l'initialisation...
  ChooserEncoder encoder(base);

  ChooserEncryptor encryptor;
  ChooserEvaluator evaluator;

  //size of one coeff in the chosen basis
  int size_coeff = (base - 1)/2;

  //elem_label represents one element  of the binary decomp of the label
  ChooserPoly elem_label(1,size_coeff);

  ChooserPoly result;

  //Pour encoding en base 3
  ChooserPoly value(ceil(log(bound_value)/log(base)), size_coeff);//ou different second terme ??


  //when we put 0 for the first term of the mult, it won't give accurate plain_modulus != when we use 1...
  ChooserPoly mult = evaluator.multiply(get_label(encoder, encryptor, evaluator, elem_label, 0, size_label - 1), value);

  result = copyPoly(mult);
  ChooserPoly cp = copyPoly(mult);

  //cout << "add copies" << endl;

  for (int i = 1; i < (1<<size_label)*nb_users; i++){
    result = evaluator.add(cp, result);
    }

  cout << endl << "Time spent simulating computation : " << endl;
  dispTime(start_custom);
  clock_t start_select = clock();

  //cout << "select parameters" << endl;
  bool select_ok = evaluator.select_parameters(result, parms);
  cout << "Select return value  : " << select_ok << endl;

  cout << endl << "Time spent by the library to select accurate parameters : " << endl;
  dispTime(start_select);
  
}

//data contains size_bin encrypted bits of label without the encrypted value of data (not useful for noise growth)
//Here we want to check whether the encrypted label is the same as the one in tab_bin_label
ChooserPoly get_label(ChooserEncoder &encoder, ChooserEncryptor &encryptor,ChooserEvaluator &evaluator, ChooserPoly elem_label, int index_start, int index_end){

  if (index_end == index_start){
    return equals(encoder, evaluator, elem_label);

  }
  else if (index_end - index_start == 1){
    return evaluator.multiply(equals(encoder, evaluator, elem_label), equals(encoder, evaluator, elem_label));
  }
  
  else{
    return evaluator.multiply(get_label(encoder, encryptor, evaluator, elem_label, index_start, floor((index_start+index_end)/2)), get_label(encoder, encryptor, evaluator, elem_label, floor((index_start+index_end)/2)+1, index_end));
  }

}

//"returns an encrypted value of one if the poly p encrypts i, and an encrypted value of zero if not."
ChooserPoly equals(ChooserEncoder &encoder, ChooserEvaluator &evaluator, ChooserPoly elem_label){

  return evaluator.add_plain(evaluator.negate(elem_label), encoder.encode(1));
  //more noise when we want to match zero so let's always compute this case.
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


// Timer function
void dispTime(clock_t cBeginning) {
  // Displays the elapsed time between cBeginning and the current time
  cout << "Time : " << (clock() - cBeginning) / ((double) CLOCKS_PER_SEC) << " seconds." << endl << endl;
}
