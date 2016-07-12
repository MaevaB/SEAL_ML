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

// Indicator function for 0
BigPolyArray indicatorZero(BigPolyArray &encrypted, Evaluator &evaluator, BigPolyArray &one) {
  // "one" here will be the encrypted value of 1
  return evaluator.sub( one, encrypted);
}

void intToTabBin(unsigned int num, int *res, int size_label) {
  // At the end of this function, "res" contains a table of the bit decomposion of "num" (e.g. : res = [0,1,0,0,1,0] for num = 10 with size_label = 6)
  if (num > (1 << size_label)) {
    cout << "Number is bigger than the maximum" << endl;
    return;
  }

  for (int i=0; i<size_label; i++) {
    res[size_label-i-1] = (num & (1 << i)) ? 1 : 0;
  }
}

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


//"returns an encrypted value of one if the poly p encrypts i, and an encrypted value of zero if not."
ChooserPoly equals(ChooserEncoder &encoder, ChooserEvaluator &evaluator, ChooserPoly elem_label){

  return evaluator.add_plain(evaluator.negate(elem_label), encoder.encode(1));
  //more noise when we want to match zero so let's always compute this case.
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
  //cout << "Select return value  : " << select_ok << endl;

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

BigPolyArray match_func (Evaluator &evaluator, vector <BigPolyArray> &label, int beg, int end){
	if (end-beg == 0) return label[beg];
	else if (end-beg == 1) return evaluator.multiply(label[beg], label[end]);
	else return evaluator.multiply(match_func(evaluator, label, beg, floor((end+beg)/2)), match_func(evaluator, label, floor((end+beg)/2) +1, end));
}


// INDICATIVE FUNCTION
//int bin_decom_label[size_label]
BigPolyArray ind_function( Encryptor &encryptor, BalancedEncoder &encoder, Evaluator &evaluator, int *bin_decomp_label, vector <BigPolyArray> &user, BigPolyArray &one, int size_label){

	vector <BigPolyArray> encrypted_label_ind_func(size_label);
	
	// We apply the indicative functions for each one of the bits of the label binary decomposition
	for (int i=0; i<size_label; ++i){
		if (bin_decomp_label[i] == 0){
			encrypted_label_ind_func[i] = evaluator.sub(one, user[i])	;
		}else{
			encrypted_label_ind_func[i] =  user[i];
		}
	}
	return match_func(evaluator, encrypted_label_ind_func, 0, size_label-1);
}


// THis fucntion returns a sommation of all the values related to a label passed as parameter
BigPolyArray stat (vector< vector < vector <BigPolyArray>>> &users, Encryptor &encryptor, BalancedEncoder &encoder, Evaluator &evaluator, unsigned int label, BigPolyArray &one, int size_label){
	vector < BigPolyArray > tmp_values;
	BigPolyArray tmp;
	int *bin_decomp = (int *)malloc(sizeof(int) * size_label) ;
	
	// We calculate the binary representation of the label 
	intToTabBin( label, bin_decomp, size_label);
	cout << "représentation binaire du label : ";
	dispTab(bin_decomp, size_label);
	// We apply indicative functions for the encrypted table
	tmp_values.clear();
	//users.size --> NB_USERS ?
	for (size_t i=0; i < users.size(); ++i){
		for (size_t j=0; j<users.at(i).size(); ++j){
		  tmp = (BigPolyArray) 	evaluator.multiply( ind_function(encryptor, encoder, evaluator, bin_decomp, users.at(i).at(j), one, size_label), users.at(i).at(j)[size_label]); 
			//cout << tmp[1].to_string()<< endl << endl << endl << endl;
			tmp_values.push_back(tmp);
		}
	}
	// We return the sum of all the values of tmp_values
	return evaluator.add_many(tmp_values);
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
   
    if (base%2 == 0){
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

  cout << "Total time for generating accurate parameters : " << cout;
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


  BigPolyArray one = encryptor.encrypt(encoder.encode(1));


  //Beginning of init params for test
  vector<vector<vector<BigPolyArray> > > dataBase;
  vector<vector<BigPolyArray> > user;

  /* 
     Each row of the user dataBase is as folows :

     [E(b_n), E(b_n-1),..., E(b_1), E(b_0), E(v)]

     Where E(b_a) is the encrypted value of the a-th bit of the bit decomposition of the label (which is an integer)
     And E(v) is the encrypted value of the corresponding value

     e.g. : [E(0), E(1), E(0), E(1), E(34)] would correspond to the entry "5:34" where 5 would be "taking the bus" for example
  */
  vector <BigPolyArray> tmpRow(size_label + 1);
  
  clock_t start_database = clock();

  srand(time(NULL));

  cout << "Generating a random " << NB_USERS << " users long database..." << endl;

  int *tmpBitDecomp = (int*)malloc(sizeof(int) * size_label) ;
  int tmpRand;
  cout << "users list generation ... " << endl; 

  for (int i=0; i<NB_USERS; i++) {
    for (int j=0; j< (1<<size_label); j++) {
      // We do not add the null values to the database (which is the whole point of this method)
      tmpRand = rand() % bound_value;
      if (tmpRand == 0)	continue;
      // We take the bit decomposition of the label
      intToTabBin(j, tmpBitDecomp, size_label);
    
      for (int k=0; k<size_label; k++) {
	// We add the encrypted version of the table in the result vector
	tmpRow[k] = encryptor.encrypt(encoder.encode(tmpBitDecomp[k]));
      }
      // Finally, we add the encrypted value at the end
      tmpRow[size_label] = (encryptor.encrypt(encoder.encode(tmpRand)));
      user.push_back(tmpRow);
      
    }
    dataBase.push_back(user);
    user.clear();
  }
  cout << "...generation complete." << endl << endl;;
  cout << "Time for generating database : " << endl;
  dispTime(start_database);


  clock_t computation = clock();
  BigPolyArray stat_result = stat(dataBase, encryptor, encoder, evaluator, 5, one, size_label);
	
  cout << endl<< "label 5 : " << encoder.decode_int64(decryptor.decrypt(stat_result)) << endl;

  cout << endl << "Time spent on computation to find the data we want :" << endl;
  dispTime(computation);

  //Relevant ?? irl we wouldn't generate a database since it would already be there ?
  cout << endl << "Total time :" << endl;
  dispTime(start);
  return 0;
}
