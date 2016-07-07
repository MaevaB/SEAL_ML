#ifndef MAIN_N2
#define MAIN_N2
#include <vector>
#include <unistd.h>
#include <ctime>
#include <cstring>
#include <fstream>

#include "seal.h"

using namespace std;
using namespace seal;

void func(bool test=false);
void dixLignes();
BigPoly calcul_variance(Evaluator &evaluator, BalancedFractionalEncoder &encoder, vector<BigPolyArray> &encrypte_tab, Encryptor &encryptor);
BigPoly exponentiationNaiveRec(const BigPolyArray &encrypte, uint64_t puissance, Evaluator &evaluator, Encryptor &encryptor, BalancedEncoder &encoder);
BigPoly exponentiationRapide(const BigPolyArray &encrypte, uint64_t puissance, Evaluator &evaluator, Encryptor &encryptor, BalancedEncoder &encoder);
BigPoly calcul_moyenne_ponderee(Evaluator &evaluator, BalancedFractionalEncoder &encoder, vector<BigPolyArray> &encrypte_tab, vector<double> coefficients);
BigPoly calcul_moyenne(Evaluator &evaluator, BalancedFractionalEncoder &encoder, vector<BigPolyArray> &encrypte_tab);
void afficherTempsEcoule(clock_t cDebut);
void afficherPoly(BigPoly poly, string nomPoly);
void afficherPoly(BigPolyArray poly, string nomPoly);//Parfois les polynômes à afficher sont chiffrés et parfois non.
void afficher_tableau(vector<double> &tab);
int menu();
void dechiffrement(BigPoly secret_key, EncryptionParameters parms, BigPolyArray encrypte, bool estUnDouble=false);

#endif
