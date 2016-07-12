#include <vector>
#include <unistd.h>
#include <ctime>
#include <cstring>
#include <cmath>
#include <fstream>
#include <ctime>

#include "seal.h"

#ifndef MAX_BITS
#define MAX_BITS 5

#endif

#ifndef NB_USERS
#define NB_USERS 1
#endif

#ifndef NB_ROWS
#define NB_ROWS 20
#endif

using namespace std;
using namespace seal;

// Indicator function for 0
BigPolyArray indicatorZero(BigPolyArray &encrypted, Evaluator &evaluator, BigPolyArray &one) {
  // "one" here will be the encrypted value of 1
  return evaluator.sub( one, encrypted);
}

void intToTabBin(unsigned int num, int **res) {
  // At the end of this function, "res" contains a tabler of the bit decomposion of "num" (e.g. : res = [0,1,0,0,1,0] for num = 10 with MAX_BITS = 6)
  if (num > (1 << MAX_BITS)) {
    cout << "Number is bigger than the maximum" << endl;
    return;
  }

  *res = (int *) (malloc(MAX_BITS * sizeof(int)));

  for (unsigned int i=0; i<MAX_BITS; i++) {
    (*res)[MAX_BITS-i-1] = (num & (1 << i)) ? 1 : 0;
  }
}

void dispTab(int *tab, int len) {
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

// MAtching function 

BigPolyArray match_func (Evaluator &evaluator, vector <BigPolyArray> &label, int beg, int end){
	if (end-beg == 0) return label.at(beg);
	else if (end-beg == 1) return evaluator.multiply(label.at(beg), label.at(end));
	else return evaluator.multiply(match_func(evaluator, label, beg, floor((end+beg)/2)), match_func(evaluator, label, (end+beg)/2 +1, end));
}


// INDICATIVE FUNCTION
BigPolyArray ind_function( Encryptor &encryptor, BalancedEncoder &encoder, Evaluator &evaluator, int **bin_decomp_label, vector <BigPolyArray> &user, BigPolyArray &one){

	vector <BigPolyArray> encrypted_label_ind_func(MAX_BITS);
	
	// We apply the indicative functions for each one of the bits of the label binary decomposition
	for (int i=0; i<MAX_BITS; ++i){
		if ((*bin_decomp_label)[i] == 0){
			encrypted_label_ind_func[i] = (indicatorZero(user[i], evaluator, one));
		}else{
			encrypted_label_ind_func[i] = ( user[i]);
		}
	}
	//return match_func(evaluator, encrypted_label_ind_func, 0, MAX_BITS-1);
	return encrypted_label_ind_func[1];
}

// THis fucntion returns a sommation of all the values related to a label passed as parameter
BigPolyArray stat (vector< vector < vector <BigPolyArray>>> &users, Encryptor &encryptor, BalancedEncoder &encoder, Evaluator &evaluator, unsigned int label, BigPolyArray &one){
	vector < BigPolyArray > tmp_values;
	int *bin_decomp;
	
	// We calculate the binary representation of the label 
	intToTabBin( label, &bin_decomp);
	dispTab(bin_decomp, MAX_BITS);
	// We apply indicative functions for the encrypted table
	for (size_t i=0; i < users.size(); ++i){
		for (size_t j=0; j<users.at(i).size(); ++j){
			tmp_values.push_back(evaluator.multiply(ind_function(encryptor, encoder, evaluator, &bin_decomp, users.at(i).at(j), one), users.at(i).at(j)[MAX_BITS]));
		}
	}
	// We return the somation of all the values of tmp_values
	return evaluator.add_many(tmp_values); 
}

// *********** MAIN **********************
int main(int argc, char **argv) {
  
  // Encryption parameters
  EncryptionParameters parms;

  parms.poly_modulus() = "1x^2048 + 1";
  parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
  parms.plain_modulus() = 1 << 8;
  parms.decomposition_bit_count() = 32;
  parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
  parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

  cout << "Encryption parameters : " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
       << parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;

  // Encoder for integers                                                                                                                                                         
  BalancedEncoder encoder(parms.plain_modulus());

  // Timer
  clock_t beginning = clock();

  // Key generation
  cout << "Generating keys..." << endl;
  KeyGenerator generator(parms);
  generator.generate();
  cout << "...key generation complete." << endl;
  BigPolyArray public_key = generator.public_key();
  BigPoly secret_key = generator.secret_key();

  dispTime(beginning);

  Encryptor encryptor(parms, public_key);
  Evaluator evaluator(parms);
  Decryptor decryptor( parms, secret_key);

  BigPolyArray one = encryptor.encrypt(encoder.encode(1));
  
  vector<vector<vector<BigPolyArray> > > dataBase;
  vector<vector<BigPolyArray> > user;

  /* 
     Each row of the user dataBase is as folows :

     [E(b_n), E(b_n-1),..., E(b_1), E(b_0), E(v)]

     Where E(b_a) is the encrypted value of the a-th bit of the bit decomposition of the label (which is an integer)
     And E(v) is the encrypted value of the corresponding value

     e.g. : [E(0), E(1), E(0), E(1), E(34)] would correspond to the entry "5:34" where 5 would be "taking the bus" for example
  */
  vector<BigPolyArray> tmpRow(MAX_BITS + 1);
  
  cout << "Generating a random " << NB_USERS << " users long database..." << endl;
  beginning = clock();

  int *tmpBitDecomp;
  int tmpRand;
	  
  for (int i=0; i<NB_USERS; i++) {
    for (int j=0; j<(1<<MAX_BITS); j++) {
      // We do not add the null values to the database (which is the whole point of this method)
      tmpRand = rand() % 10;
      if (tmpRand == 0)	continue;
      // We take the bit decomposition of the label
      intToTabBin(j, &tmpBitDecomp);
    
      for (int k=0; k<MAX_BITS; k++) {
	// We add the encrypted version of the tabler in the result vector
	tmpRow[i] = encryptor.encrypt(encoder.encode(tmpBitDecomp[k]));
      }
      // Finally, we add the encrypted value at the end
      tmpRow[MAX_BITS] = (encryptor.encrypt(encoder.encode(tmpRand)));
      user.push_back(tmpRow);
      
      tmpRow.clear();
    }
    dataBase.push_back(user);
    user.clear();
  }
	BigPolyArray stat_result = stat(dataBase, encryptor, encoder, evaluator, 31, one);
  cout << "valeur 4 : " << encoder.decode_int64(decryptor.decrypt(stat_result)) << endl;
  cout << "...generation complete." << endl;
  dispTime(beginning);

  return 0;
}
