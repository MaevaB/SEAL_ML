#include <vector>
#include <unistd.h>
#include <ctime>
#include <cstring>
#include <cmath>
#include <fstream>
#include <ctime>

#include "seal.h"

#ifndef CLEAR
#define CLEAR "clear"
#endif


using namespace std;
using namespace seal;

void func(bool test);

int main(int argc, const char* argv[]) {
  // Lancer le programme avec l'argument -t pour lancer le mode de test
  bool test = ((argc > 1) && !strcmp(argv[1], "-t")) ? true : false;
    
  func(test);

  return 0;
}

void dixLignes() {
  // Saute dix lignes

  for (int i=0; i<10; i++) {
    cout << endl;
  }
}

void continuer() {
  cout << "Appuyer sur ENTRER pour continuer";
  cin.ignore();
  cin.get();
  cout << endl;

}

void dechiffrement(BigPoly secret_key, EncryptionParameters parms, BigPolyArray encrypte, bool estUnDouble=false) {
  // Dechiffrement de la valeur

  Decryptor decryptor(parms, secret_key);
  BigPoly decrypte = decryptor.decrypt(encrypte);

  // Decodage du polynome
  if (estUnDouble) {
    BalancedFractionalEncoder fracEncoder(parms.plain_modulus(), parms.poly_modulus(), 256, 128);
    double decode = fracEncoder.decode(decrypte);
  	cout << decode << endl;
  }
  else {
    BalancedEncoder encoder(parms.plain_modulus());
    int decode = encoder.decode_int64(decrypte);
  	cout << decode << endl;
  }
}

BigPolyArray calcul_moyenne(Evaluator &evaluator, BalancedFractionalEncoder &encoder, vector<BigPolyArray> &encrypte_tab) {
  BigPolyArray sommeCoeffs = evaluator.add_many(encrypte_tab);

  return evaluator.multiply_plain(sommeCoeffs, encoder.encode(1.0/encrypte_tab.size()));
}

BigPolyArray calcul_variance(Evaluator &evaluator, BalancedFractionalEncoder &encoder, vector<BigPolyArray> &encrypte_tab, Encryptor &encryptor) {
  size_t n = encrypte_tab.size();
  BigPolyArray moy = calcul_moyenne(evaluator, encoder, encrypte_tab);
  BigPolyArray moyenneTab = evaluator.multiply(encryptor.encrypt(encoder.encode(-1)), evaluator.multiply(moy, moy));
  
  BigPolyArray res = encryptor.encrypt(encoder.encode(0));
  
  for (size_t i=0; i<n; i++) {
    res = evaluator.add(res, evaluator.multiply(encrypte_tab.at(i), encrypte_tab.at(i)));
  }

  res = evaluator.multiply_plain(res, encoder.encode(1.0/n));
  res = evaluator.add(res, moyenneTab);
  
  return res;
}
// EXPONENTIATION NAIVE AVEC DES ENTIERS 
BigPolyArray exponentiationNaiveRec(const BigPolyArray &encrypte, uint64_t puissance, Evaluator &evaluator, Encryptor &encryptor, BalancedEncoder &encoder) {
  // Version recursive de l'exponentiation naive : on fait "puissance" multiplications au total --> Beaucoup de bruit
  
  if (puissance < 0) {
    cout << "Erreur, puissance < 0" << endl;
    return encrypte;
  }

  if (puissance == 0) {
    return encryptor.encrypt(encoder.encode(1));
  }

  if (puissance == 1) {
    return encrypte;
  }

  return evaluator.multiply(encrypte, exponentiationNaiveRec(encrypte, puissance - 1, evaluator, encryptor, encoder));
}
// EXPONENTIATION RAPIDE AVEC DES ENTIERS
BigPolyArray exponentiationRapide(const BigPolyArray &encrypte, uint64_t puissance, Evaluator &evaluator, Encryptor &encryptor, BalancedEncoder &encoder) {
  // Exponentiation rapide : on fait ... multiplications au total --> Moins de bruit

  if (puissance < 0) {
    cout << "Erreur, puissance < 0" << endl;
    return encrypte;
  }

  if (puissance == 0) {
    return encryptor.encrypt(encoder.encode(1));
  }

  if (puissance == 1) {
    return encrypte;
  }

  if (!(puissance%2)) {
    return exponentiationRapide(evaluator.multiply(encrypte, encrypte), puissance/2, evaluator, encryptor, encoder);
  }

  return evaluator.multiply(encrypte, exponentiationRapide(evaluator.multiply(encrypte, encrypte), (puissance - 1)/2, evaluator, encryptor, encoder));
}
//EXPONENTIATION RAPIDE AVEC DES RÉELS
BigPolyArray exponentiationRapideReel(const BigPolyArray &encrypte, uint64_t puissance, Evaluator &evaluator, Encryptor &encryptor, BalancedFractionalEncoder &encoder){
	if (puissance < 0) {
    cout << "Erreur, puissance < 0" << endl;
    return encrypte;
  }

  if (puissance == 0) {
    return encryptor.encrypt(encoder.encode(1));
  }

  if (puissance == 1) {
    return encrypte;
  }

  if (!(puissance%2)) {
    return exponentiationRapideReel(evaluator.multiply(encrypte, encrypte), puissance/2, evaluator, encryptor, encoder);
  }

  return evaluator.multiply(encrypte, exponentiationRapideReel(evaluator.multiply(encrypte, encrypte), (puissance - 1)/2, evaluator, encryptor, encoder));
}

BigPolyArray calcul_moyenne_ponderee(Evaluator &evaluator, BalancedFractionalEncoder &encoder, vector<BigPolyArray> &encrypte_tab, vector<double> coefficients) {
  size_t size = encrypte_tab.size();
  BigPolyArray res;
  if (size != coefficients.size() || size == 0) {
    cout << "ERREUR : il n'y a pas autant de coefficients que de valeurs !" << endl;
    return res;
  }
  
  vector<BigPolyArray> encrypte_produits;
  double quotient = 0.0;
  BigPoly inverseQuotient;
  cout << "ok" << endl;
  // Encodage des coefficients
  for (size_t i=0; i<size; i++) {
    quotient += coefficients.at(i);
  }
  inverseQuotient = encoder.encode(1.0/quotient);
  
  cout << "Calcul de la moyenne ponderee pour le tableau..." << endl;

  // Multiplication des coefficients par les valeurs du tableau
  for (size_t i=0; i<size; i++) {
    encrypte_produits.push_back(evaluator.multiply_plain(encrypte_tab.at(i), encoder.encode(coefficients.at(i))));
  }
  
  // Somme des valeurs du tableau
  BigPolyArray encrypte_somme = evaluator.add_many(encrypte_produits);
 
  // Division par la taille (multiplication par l'inverse de la taille)
  res = evaluator.multiply_plain(encrypte_somme, inverseQuotient);

  return res;
}

// ------- QUELQUES STATISTIQUES SUR L'UTILISATION DES MOYENS DE TRANSPORT SELON LE CLIMAT ------//
BigPolyArray stat(vector <vector <vector <BigPolyArray> > > &moyen_de_transport, int moyen, int clim, Evaluator &evaluator, BalancedEncoder &encoder, Encryptor &encryptor){
  /*Dans tous les cas, on va construire un nouveau tableau de chiffrés contenant 1 pour 
     des utilisateurs ayant utilisé moyen, et 0 pour les autres. */
  BigPolyArray somme;
  BigPolyArray produit;
  vector <BigPolyArray> filtre;
  switch  (moyen){
    case 0 : 
      for (size_t i=0; i < moyen_de_transport.size(); i++){
	somme = evaluator.add(moyen_de_transport[i][clim].at(0), moyen_de_transport[i][clim].at(1));
	produit = evaluator.multiply(moyen_de_transport[i][clim].at(0), moyen_de_transport[i][clim].at(1));
        filtre.push_back(evaluator.add((encryptor.encrypt(encoder.encode(1))), evaluator.negate(evaluator.add(somme, evaluator.negate(produit)))));
    }
	break;
    case 1 :
      for (size_t i=0; i < moyen_de_transport.size(); i++){
       	produit = evaluator.multiply(moyen_de_transport[i][clim].at(0), moyen_de_transport[i][clim].at(1));
        filtre.push_back(evaluator.add(moyen_de_transport[i][clim].at(1), evaluator.negate(produit)));
    }
	break;
    case 2 :
       for (size_t i=0; i < moyen_de_transport.size(); i++){
	 produit = evaluator.multiply(moyen_de_transport[i][clim].at(0), moyen_de_transport[i][clim].at(1));
        filtre.push_back(evaluator.add(moyen_de_transport[i][clim].at(0), evaluator.negate(produit)));
 	}
	break;
    case 3 :
      for (size_t i=0; i < moyen_de_transport.size(); i++){
      produit = evaluator.multiply(moyen_de_transport[i][clim].at(0), moyen_de_transport[i][clim].at(1));
	 filtre.push_back(produit);
	}
	break;
  }

       return evaluator.add_many(filtre);
}

void afficherTempsEcoule(clock_t cDebut) {
  // Affiche le temps ecoule entre cDebut et maintenant
  
  cout << "Temps : " << (clock() - cDebut) / ((double) CLOCKS_PER_SEC) << " secondes." << endl << endl;
}

void afficherPoly(BigPoly poly, string nomPoly) {
  // Affiche le polynome poly
  
  cout << "Polynome " << nomPoly << " : " << poly.to_string() << endl;

  // Courte pause pour laisser a l'ordinateur le temps d'afficher le polynome s'il est gros
  sleep(0.5);
  
  dixLignes();
}
 // Affiche un tableau de réels
void afficher_tableau (vector<double> &tab) {
  cout << "[";
  size_t size = tab.size();
  for (size_t i=0; i<size; i++) {
    cout << tab[i] << ((i != size - 1) ? " " : "");
  }
  cout << "]" << endl;
}
// Fonction qui remplit un tableau aléatoirement 

void remplir_tab_reel(int taille, vector <double> &tab){
	for (int i=0; i<taille; i++){
  	tab.push_back((double)(rand()%100)/12);
  }
}


// Cette fonction remplit un tableau de réels mais ne les chiffre pas, elle ne fait que les encoder

void encode_tab_reel(vector <BigPoly> &tab, vector <double> &tab1, BalancedFractionalEncoder &encoder){
	for (unsigned int i=0; i<tab1.size(); i++){
		tab.push_back(encoder.encode(tab1.at(i)));
  }
}


void encrypt_tab(vector <BigPolyArray> &encrypt, vector <BigPoly> &encode, Encryptor &encryptor){
	for (unsigned int i=0; i<encode.size(); i++){
		encrypt.push_back(encryptor.encrypt(encode.at(i)));
	}
}
// La fonction qui affiche les polynômes de type BigPolyArray

void afficherPoly(BigPolyArray poly, string nomPoly){
// Affiche les deux  polynômes qui conctituent poly
  
  cout << "Polynome " << nomPoly << " : " << poly[0].to_string() << endl;
  cout << "Polynome " << nomPoly << " : " << poly[1].to_string() << endl;

  // Courte pause pour laisser a l'ordinateur le temps d'afficher le polynome s'il est gros
  sleep(0.5);
  
  dixLignes();
}



int menu() {
  // Retourne le choix de l'utilisateur
  int nb;

  cout << "\t\t\t***MENU***" << endl << endl;
  cout << "1.     Dechiffrer les valeurs" << endl;
  cout << "2.     Additionner les valeurs chiffrees" << endl;
  cout << "3.     Multiplier les valeurs chiffrees" << endl;
  cout << "4.     Afficher les cles" << endl;
  cout << "5.     Afficher des valeurs encryptes" << endl;
  cout << "6.     Exponentiation rapide VS exponentiation naïve" << endl;
  cout << "7.     Exemple d'un calcul de moyenne pondérée" << endl;
  cout << "8.     Exemple d'un calcul de variance" << endl;
  cout << "9.     statistiques" << endl;
  cout << "Autre. Sortie du programme" << endl << endl;
  
  cin >> nb;
  
  return nb;
}


// ---------------------------FONCTION PRINCIPALE---------------------------
void func(bool test=false) {
  system(CLEAR);
  // Parametres de chiffrement
  EncryptionParameters parms;
  
  parms.poly_modulus() = "1x^2048 + 1";
  parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
  parms.plain_modulus() = 1 << 12;
  parms.decomposition_bit_count() = 32;
  parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
  parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

  cout << "Parametres de chiffrement : " << parms.poly_modulus().significant_coeff_count() << " coefficients avec "
       << parms.coeff_modulus().significant_bit_count() << " bits par coefficient" << endl;

  // Choix des valeurs a encrypter
  int val1, val2;
  BigPoly encode1;
  BigPoly encode2;
	BigPolyArray encrypte1;
	BigPolyArray encrypte2;
  
  // Encodeur pour les entiers
  BalancedEncoder encoder(parms.plain_modulus());
  // Encodeur pour les réels
  BalancedFractionalEncoder fracEncoder(parms.plain_modulus(), parms.poly_modulus(), 256, 128);
	
	
  // Timer
  clock_t debut = clock();

  EvaluationKeys evaluation_keys;
    
  // Generation des cles
  cout << "Generation des cles..." << endl;
  KeyGenerator generator(parms);
  generator.generate();
  cout << "...generation des cles terminee." << endl;
  BigPolyArray public_key = generator.public_key();
  BigPoly secret_key = generator.secret_key();
  //evaluation_keys = generator.evaluation_keys();
  
  afficherTempsEcoule(debut);
  debut = clock();

  Encryptor encryptor(parms, public_key);
  afficherTempsEcoule(debut);
  
  // Evaluator : gere les opérations sur les donnees chiffrees
  Evaluator evaluator(parms);
  
  // Polynome temporaire utilise pour les resultats d'operations
  // (on l'encrypte pour qu'il ait la bonne forme, le programme renvoie une exception "std::invalid_argument" si on ne le fait pas)
  BigPolyArray tmp = encryptor.encrypt(encoder.encode(0));
  
  srand(time(NULL));
  
  int TAB_SIZE;
  // Tableau de valeurs                                                                                                                                               
  vector <double> tab ;
  vector <BigPoly> encoded_tab;
  vector <BigPolyArray> encrypted_tab;
  
  // Tableau de coefficients                                                                                                                                                                         
  vector <double> coeffs;
  vector<BigPoly> encoded_coeffs;
  
  bool sortie = false;
  double valeur;
  int puissance;
  sleep(1);
  
  BigPoly temp; // Polynôme temporaire à utiliser dans les differents calculs.

  /* Pour les statistiques, on part du principe que toutes les valeurs numériques sont converties en binaire avant d'être chiffrées, donc chaque nombre est représentés par un tableau de valeurs binaires.
     Pour simplifier, on va fixer la taille du tableau représentant les nombres en binaire. Dans notre éxemple, nous allons faure des statistques sur l'utilisation des differents moyens de transport par un certain nombre de personnes selon le climat, donc nous avons 4 valeurs possibles, correspondant au moyen de transport utilisé, et deux autres correspondant au climat, selon le tableau suivant:

Climat     | valeur numérique correspondante   |  représentation binaire
-------------------------------------------------------------------------
soleil     |  0                                |  00
pluie      |  1                                |  01
-------------------------------------------------------------------------
-------------------------------------------------------------------------
Moyen de transport | val. numérique            | rep. binaire
-------------------------------------------------------------------------
voiture            | 0                         | 00
metro              | 1                         | 01 
bus                | 2                         | 10
velib              | 3                         | 11
-------------------------------------------------------------------------
Dans cet éxemple, la taille du tableau représentant chaque valeur numérique est 2, 
car c'est suffisant pour quatre valeurs.
  */

  /* Pour illustrer ce qui précède avec un simple éxemple, nous allons tirer aléatoirement deux fois
 un moyen de transport pour 1000 personnes differentes, une fois quand il fait beau et une autre 
quand il pleut, et nous allons compter le nombres de personnes qui ont utilisé chaque moyen de 
transport dans chacunes des deux conditions climatiques étudiées. */

  vector < vector <vector <BigPolyArray> > >moyen_de_transport;
  vector <vector <BigPolyArray> > alea;
  vector <BigPolyArray> temp_alea(2);
  
  
  do {
    system(CLEAR);
    debut = clock();
    switch (menu()) {
    case 1 :
    
    	cout << "Entrez la valeur" << endl;
    	cin >> val1;
    	cout << "chiffrement de la valeur ..." << endl;
    	encode1 = encoder.encode(val1);
    	encrypte1 = encryptor.encrypt(encode1);
    	cout << "... Valeur chiffrée." << endl;
    	cout << "Déchiffrement de la  ... " << endl;
    	cout << "valeur  = ";
      dechiffrement(secret_key, parms, encrypte1);
      afficherTempsEcoule(debut);
      continuer();
      break;
      
    case 2 :
    
      cout << endl << "Addition de deux chiffrés" << endl;
      cout << "Entrez la valeur 1 " << endl;
      cin >> val1;
      cout << "Entrez la valeur 2 " << endl;
      cin >> val2;
      cout << "chiffrement de la valeur 1 ..." << endl;
    	encrypte1 = encryptor.encrypt(encoder.encode(val1));
    	cout << "Valeur 1 chiffrée." << endl;
    	cout << "Chiffrement de la valeur 2 ... "<< endl;
  		encrypte2 = encryptor.encrypt(encoder.encode(val2));
  		cout << "valeur 2 chiffrée ." << endl;
  		cout << "Addition  des deux chiffrés..." << endl;
      tmp = evaluator.add(encrypte1, encrypte2);
      cout << "Dechiffrement du résultat ..." << endl;
      dechiffrement(secret_key, parms, tmp);
      afficherTempsEcoule(debut);
      continuer();
      break;
      
    case 3 :
      
      cout << endl << "Multiplication de deux chiffrés" << endl;
      cout << "Entrez la valeur 1 " << endl;
      cin >> val1;
      cout << "Entrez la valeur 2 " << endl;
      cin >> val2;
      cout << "chiffrement de la valeur 1 ..." << endl;
    	encrypte1 = encryptor.encrypt(encoder.encode(val1));
    	cout << "Valeur 1 chiffrée." << endl;
    	cout << "Chiffrement de la valeur 2 ... "<< endl;
  		encrypte2 = encryptor.encrypt(encoder.encode(val2));
  		cout << "valeur 2 chiffrée ." << endl;
  		cout << "Multiplication des deux chiffrés" << endl;
      tmp = evaluator.multiply(encrypte1, encrypte2);
      cout << "Dechiffrement du résultat  ..." << endl;
      dechiffrement(secret_key, parms, tmp);
      afficherTempsEcoule(debut);
      continuer();
      break;
      
    case 4 :
      afficherPoly(public_key, "public_key");
      afficherPoly(secret_key, "secret_key");
      afficherTempsEcoule(debut);
      continuer();
      break;
      
    case 5 :
    	cout << "Entrez une valeur à chiffrer" << endl;
    	cin >> val1;
    	encrypte2 = encryptor.encrypt(encoder.encode(val1));
      afficherPoly(encrypte2, "Valeur");
      afficherTempsEcoule(debut);
      continuer();
      break;
      
    case 6 :
   	
      cout << endl << "Entrez la valeur : " << endl << endl;
      cin >> valeur;
      cout << "Puissance ?" << endl;
      cin >> puissance;
      encode1 = fracEncoder.encode(valeur);
      encrypte1 = encryptor.encrypt(encode1);
      if (valeur == (int) valeur){
			// exponentiation d'un entier
      // Methode rapide :
      cout << endl << "Methode rapide..." << endl;
      tmp = exponentiationRapide(encrypte1, puissance, evaluator, encryptor, encoder);
      afficherTempsEcoule(debut);
      dechiffrement(secret_key, parms, tmp);
      
      debut = clock();
      // Methode naive recursive :
      cout << endl << "Methode naive recursive..." << endl;
      tmp = exponentiationNaiveRec(encrypte1, puissance, evaluator, encryptor, encoder);
      afficherTempsEcoule(debut);
      dechiffrement(secret_key, parms, tmp);
      
      } 
      else{
      	//Exponentiation d'un réel
      	tmp = exponentiationRapideReel(encrypte1, puissance, evaluator, encryptor, fracEncoder);
      	afficherTempsEcoule(debut);
      	dechiffrement(secret_key, parms, tmp);
      }
      continuer();
      break;
     
    case 7 :
    	cout << "*****************************************\n On genere un tableau de valeurs et un tableau de coefficients, puis\n on encode et on chiffre les valeurs, tandis \nque les coefficients sont juste encodés en polynômes, car \non suppose que les coefficients ne sont pas forcément secrets.\n****************************************" << endl;
    	cout << "Entrez la taille des deux tableaux "  << endl;
    	cin >> TAB_SIZE;
      cout << endl << "Calcul de la moyenne pour le tableau : ";
 			remplir_tab_reel(TAB_SIZE, tab);
 			afficher_tableau(tab);
 			cout << "encodage du tableau ..." << endl;
 			encode_tab_reel(encoded_tab, tab, fracEncoder);
 			cout << "términé." << endl;
 			cout << "chiffrement du tableau ..." << endl;
 			encrypt_tab(encrypted_tab, encoded_tab, encryptor);
      cout << endl << "Et coefficients : ";
 			remplir_tab_reel(TAB_SIZE, coeffs);
 			afficher_tableau(coeffs);
 			cout << "encodage des coeffs ..." << endl;
 			encode_tab_reel(encoded_coeffs, coeffs, fracEncoder);
 			cout << "terminé." << endl;
      cout << endl;

      tmp = calcul_moyenne_ponderee(evaluator, fracEncoder, encrypted_tab, coeffs);
      afficherTempsEcoule(debut);
      dechiffrement(secret_key, parms, tmp, true);
      encoded_coeffs.clear();
    	encrypted_tab.clear();
    
      continuer();
      break;
     
    case 8 :
    	cout << "Entrez la taille du tableau " << endl;
    	cin >> TAB_SIZE;
    	tab.clear();
      cout << "Calcul de la variance pour le tableau : " << endl;
      remplir_tab_reel(TAB_SIZE, tab);
      cout << "Encodage du tableau ..." << endl;
      encoded_tab.clear();
      encode_tab_reel(encoded_tab, tab, fracEncoder);
      cout << "terminé." << endl;
      cout << "chiffrement du tableau ... " << endl;
      encrypted_tab.clear();
      encrypt_tab(encrypted_tab, encoded_tab, encryptor);
      cout << "terminé." << endl;
      cout << endl;
      
      // Encodage et Cryptage du tableau de valeurs

      tmp = calcul_variance(evaluator, fracEncoder, encrypted_tab, encryptor);
      afficherTempsEcoule(debut);
      dechiffrement(secret_key, parms, tmp, true);
      encoded_coeffs.clear();
    	encrypted_tab.clear();
    
      continuer();
      break;

    case 9 :
    	cout << "Entrez la taille du tableau : " << endl;
    	cin >> TAB_SIZE;
    	
    	cout << "generation d'un tableau aléatoire ..." << endl;
    	for (int i=0; i<TAB_SIZE; i++){
			 // On tire aléatoirement les deux moyens de transport utilisés par un personne  quand il fait beau (a) et quand il pleut (b) .
			 int a, b;
			 a = rand()%4;
			 b = rand()%4;
			 temp_alea[0] = encryptor.encrypt(encoder.encode(a/2));
			 temp_alea[1] = encryptor.encrypt(encoder.encode(a%2));
			 alea.push_back(temp_alea);
			 temp_alea [0] = encryptor.encrypt(encoder.encode(b/2));
			 temp_alea [1] = encryptor.encrypt(encoder.encode(b%2));
			 alea.push_back(temp_alea);
			 //On ajoute cette personne dans le tableau moyen_de_transport.
				moyen_de_transport.push_back(alea);
				alea.clear();
			}
  		cout << "terminé." << endl;
      cout << "Soleil:" << endl;
      cout << "Le nombre de personnes ayant utilisé leur voiture personnelle est : " ;
      dechiffrement(secret_key, parms, stat(moyen_de_transport, 0, 0, evaluator, encoder, encryptor), true) ;
      cout << endl;
      cout << "Le nombre de personnes ayant utilisé le metro est : " ; dechiffrement(secret_key, parms, stat(moyen_de_transport, 1, 0, evaluator, encoder, encryptor), true) ;
      cout << endl;
      cout << "Le nombre de personnes ayant utilisé le bus est : " ; dechiffrement(secret_key, parms, stat(moyen_de_transport, 2, 0, evaluator, encoder, encryptor), true) ;
      cout << endl;
      cout << "Le nombre de personnes ayant utilisé le velib est : " ; dechiffrement(secret_key, parms, stat(moyen_de_transport, 3, 0, evaluator, encoder, encryptor), true) ;
      cout << endl << "---------------------------------" << endl;
      cout << "pluie:" << endl;
      cout << "Le nombre de personnes ayant utilisé leur voiture personnelle est : " ; dechiffrement(secret_key, parms, stat(moyen_de_transport, 0, 1, evaluator, encoder, encryptor), true) ;
      cout << endl;
      cout << "Le nombre de personnes ayant utilisé le metro est : " ; dechiffrement(secret_key, parms, stat(moyen_de_transport, 1, 1, evaluator, encoder, encryptor), true) ;
      cout << endl;
      cout << "Le nombre de personnes ayant utilisé le bus est : " ; dechiffrement(secret_key, parms, stat(moyen_de_transport, 2, 1, evaluator, encoder, encryptor), true) ;
      cout << endl;
      cout << "Le nombre de personnes ayant utilisé le velib est : " ; dechiffrement(secret_key, parms, stat(moyen_de_transport, 3, 1, evaluator, encoder, encryptor), true) ;
      continuer();
      break;
	
    default :
      cout << endl << "Sortie." << endl << endl;
      sortie = true;
      break;
    }
  } while (!sortie);
}
