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

//binary size of label (must be even)
#define SIZE_LABEL 6

//upper bound on the values associated with each label
#define BOUND_VALUE 50

//number of users
#define NB_USERS 3

//base for encoding
#define BASE 3

using namespace std;
using namespace seal;

void print_example_banner(string title);
void intToTabBin(unsigned int num, int **res, int size_label);

void custom_parameters(EncryptionParameters &parms, int size_label, int nb_users, int bound_value);
ChooserPoly get_label(ChooserEncoder &encoder, ChooserEncryptor &encryptor,ChooserEvaluator &evaluator, int *tab_bin_label, vector <ChooserPoly> & dataset, int index_start, int index_end);
ChooserPoly equals(ChooserEncoder &encoder, ChooserEvaluator &evaluator, ChooserPoly p, int i);
ChooserPoly copyPoly(ChooserPoly poly);

int main(int argc, char *argv[]){

  int size_label=0;

  //A changer plus tard
  int nb_users=NB_USERS;
  int bound_value = BOUND_VALUE;

  if (argc > 2){
    cout << "Invalid argument" << endl;
    cout << "Usage : ./distribution.exe <size_entry>" << endl;
    return 1;
  }

  if (argc == 1){
    size_label=SIZE_LABEL;
    cout << "Default parameters : size = " << size_label << endl;
  }
  
  if (argc == 2){
    size_label = atoi(argv[1]);
    cout << "User parameters : size = " << size_label << endl;
  }


  print_example_banner("Distribution");

  //Initialize parameters
  cout << "Initializing encryption parameters..." << endl;

  //Encryption parameters
  EncryptionParameters parms;
  /*parms.poly_modulus()= "1x^2048 + 1";
  parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
  parms.plain_modulus() = 1 << 8;
  */

  //Test simulation
  /*ChooserEncoder Cencoder;
  ChooserEncryptor Cencryptor;
  ChooserEvaluator Cevaluator;

  ChooserPoly p1 = Cencryptor.encrypt(Cencoder.encode(1));
  //ChooserPoly p2 = Cencryptor.encrypt(Cencoder.encode(1));
  ChooserPoly res = Cevaluator.add(p1, p1);
  Cevaluator.select_parameters(res, parms);
  */

  //Custom encryption parameters
  custom_parameters(parms, size_label, nb_users, bound_value);

    cout << "DONE" << endl;

  cout << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
       << parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;
  cout << "Plain modulus : " << parms.plain_modulus().to_string() << endl;


  if (parms.plain_modulus() < (BASE + 1)/2){
    parms.plain_modulus() = (BASE + 1)/2;
    cout << "new plain modulus : " << parms.plain_modulus().to_string() << endl;
  }


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

void custom_parameters(EncryptionParameters &parms, int size_label, int nb_users, int bound_value){
  cout << "custom parameters (this may take some time)" << endl;
  ChooserEncoder encoder;
  ChooserEncryptor encryptor;
  ChooserEvaluator evaluator;

  srand(time(NULL));

  //test for all the users or only one ? all here but computation on only one label
  //users are not separated in dataset, we only want to know how much computation has been done

  cout << "biggest label" << endl;
  int *label;
  //for the biggest label, one size_label table (binary representation) (switch to random ?)
  vector <ChooserPoly> encrypted_label;
  intToTabBin(pow(2, size_label)-1, &label, size_label);

  cout << "encrypted label" << endl;
  for (int k=0; k < size_label; k++){
    encrypted_label.push_back(encryptor.encrypt(encoder.encode(label[k])));
    //encrypted_label = chiffré du label sur lequel on base nos calculs
  }


  cout << "random label" << endl;
  //random table of zeros and ones of size size_label : will be the label we want to match
  int *tab_bin_label =(int *) malloc(size_label * sizeof(int));
  for (int j = 0; j < size_label; j++){
    tab_bin_label[j]=rand()%2;
  }

  ChooserPoly result;//=encryptor.encrypt(encoder.encode(0));
  ChooserPoly mult=encryptor.encrypt(encoder.encode(0));
  //ChooserPoly value=encryptor.encrypt(encoder.encode(bound_value)); // any info ???

  //Pour encoding en base 3
  ChooserPoly value(log(bound_value)/log(3), 1);

  //Changer la boucle pour mettre des copies de la premiere iteration
  //Since the noise is random, it wont change much from ones to zeros (?). We only compute the whole thing for the highest label (so only ones).
  cout << "calcul unique" << endl;
  mult = evaluator.multiply(get_label(encoder, encryptor, evaluator, tab_bin_label, encrypted_label, 0, size_label - 1), value);
  //result = evaluator.add(mult, result);
  result = copyPoly(mult);

  cout << "add copies" << endl;
  //ChooserPoly tmp = copyPoly(result); //++
  for (int i = 1; i < (1<<size_label)*nb_users; i++){
    //result = evaluator.add(copyPoly(mult), tmp);
    result = evaluator.add(copyPoly(mult), result);
    //tmp = copyPoly(result);
    }
  //Do we get the same noise when multiplying by a plain integer n and when adding n times ???
  //maybe/not but here we simulate addition of different ciphertexts and not plaintext mul
  cout << "select parameters" << endl;
  bool select_ok = evaluator.select_parameters(result, parms);
  cout << "Select return value  : " << select_ok << endl;
}

//data contains size_bin encrypted bits of label without the encrypted value of data (not useful for noise growth)
//Here we want to check whether the encrypted label is the same as the one in tab_bin_label
ChooserPoly get_label(ChooserEncoder &encoder, ChooserEncryptor &encryptor,ChooserEvaluator &evaluator, int *tab_bin_label, vector <ChooserPoly> & encrypted_label, int index_start, int index_end){

  if (index_end == index_start){
    return equals(encoder, evaluator, encrypted_label.at(index_start), tab_bin_label[index_start]);

  }
  else if (index_end - index_start == 1){
    return evaluator.multiply(equals(encoder, evaluator, encrypted_label.at(index_start), tab_bin_label[index_start]), equals(encoder, evaluator, encrypted_label.at(index_end), tab_bin_label[index_end]));
  }
  
  else{
    return evaluator.multiply(get_label(encoder, encryptor, evaluator, tab_bin_label, encrypted_label, index_start, floor((index_start+index_end)/2)), get_label(encoder, encryptor, evaluator, tab_bin_label, encrypted_label, ceil((index_start+index_end)/2), index_end));
  }

}

ChooserPoly equals(ChooserEncoder &encoder, ChooserEvaluator &evaluator, ChooserPoly p, int i){

  if (i == 0)
    return evaluator.add_plain(evaluator.negate(p), encoder.encode(i));
  else if (i == 1)
    return p;
  else{
    cout << "Aborting : label must be in binary (equals)" << endl;
    exit(1);
  }
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

void intToTabBin(unsigned int num, int **res, int size_label) {
  // At the end of this function, "res" contains a table of the bit decomposion of "num" (e.g. : res = [0,1,0,0,1,0] for num = 10 with MAX_BITS = 6)
  if (num > (1 << SIZE_LABEL)) {
    cout << "Number is bigger than the maximum" << endl;
    return;
    }

  *res = (int *) (malloc(size_label * sizeof(int)));

  for (unsigned int i=0; i<size_label; i++) {
    (*res)[SIZE_LABEL-i-1] = (num & (1 << i)) ? 1 : 0;
  }
}

/*void encrypt_binary_decomp(vector <int> &tab(SIZE_LABEL), vector <BigPolyArray> & encrypt_tab(SIZE_LABEL), Encryptor encryptor, Encoder encoder){

  for(int i=0; i<SIZE_LABEL; i++){
    encrypt_tab.at(i) =  encryptor.encrypt(encoder.encode(tab.at(i)));
  }
}
*/
