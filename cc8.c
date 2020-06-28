// This is CC8, a tiny block cipher written by Chandana Gamage.
// Please send any comments on the code to chandag@cse.mrt.ac.lk with subject: CC8
// Read the code to figure out how it works and how to use it.
// Last modified on 25 June 2020.

#include <stdio.h>
#include <string.h>

int IP[] = { // a 16-bit vector
	13, 9, 5, 1,
	15, 11, 7, 3,
	12, 8, 4, 0,
	14, 10, 6, 2};

int FP[] = { // a 16-bit vector (inverse of IP)
	11, 3, 15, 7,
	10, 2, 14, 6,
	9, 1, 13, 5,
	8, 0, 12, 4};

int E[] = { // a 12-bit vector to expand 8-bit vector
	7, 0, 1, 2,
	2, 3, 4, 5,
	5, 6, 7, 0};

int P[] = { // an 8-bit vector
	6, 5, 8, 7,
	4, 3, 1, 2};

int S1[4][2] = { // a 4x2 lookup table
	0, 2,
	1, 3,
	3, 0,
	2, 1};

int S2[4][2] = { // a 4x2 lookup table
	0, 3,
	2, 0,
	1, 2,
	3, 1};

int S3[4][2] = { // a 4x2 lookup table
	1, 0,
	3, 2,
	2, 3,
	0, 1};

int S4[4][2] = { // a 4x2 lookup table
	3, 2,
	1, 0,
	1, 0,
	2, 3};

int PC1[] = { // a 14-bit vector (16-bit vector with bits at 7 and 15 dropped
	6, 4, 11, 5, 1, 2, 0,
	14, 12, 13, 9, 3, 10, 8};

int PC2[] = { // a 12-bit vector (14-bit vector with bits at 3, and 8 dropped)
	6, 4, 2, 5, 0, 1,
	12, 13, 10, 9, 11, 7};

int SHIFTS[] = { // an 8 element vector
	1, 2, 2, 1, 1, 2, 2, 1};

int right_half8[8];
int left_half8[8];
int rf_subkey12[16][12];
int reverse_rf_subkey12[16][12];
int rf_output8[8];
int plaintext16[16];
int ciphertext16[16];
int key16[16];

// round function inputs are right_half8, rf_subkey (through round), and mode
// mode == 0 for encryption and mode == 1 for decryption
// output will be in rf_output8
void round_function(int round, int mode)
{
	int rf_buffer12[12];
	int rf_buffer8[8];
	int row;
	int col;
	int cell_value;

	// expansion from 8 to 12 bits
	for (int i = 0; i < 12; i++)
		rf_buffer12[i] = right_half8[E[i]];

	// xor with 12 bit subkey
	for (int i = 0; i < 12; i++)
	{
		if (mode == 0)
			rf_buffer12[i] = rf_buffer12[i] ^ rf_subkey12[round][i];
		else
			rf_buffer12[i] = rf_buffer12[i] ^ reverse_rf_subkey12[round][i];
	}

	// substitution with 4 s-boxes
	row = rf_buffer12[0] * 2 + rf_buffer12[0 + 2];
	col = rf_buffer12[0 + 1];
	cell_value = S1[row][col];
	rf_buffer8[0] = cell_value % 2;
	rf_buffer8[0 + 1] = cell_value / 2;

	row = rf_buffer12[3] * 2 + rf_buffer12[3 + 2];
	col = rf_buffer12[3 + 1];
	cell_value = S2[row][col];
	rf_buffer8[2] = cell_value % 2;
	rf_buffer8[2 + 1] = cell_value / 2;

	row = rf_buffer12[6] * 2 + rf_buffer12[6 + 2];
	col = rf_buffer12[6 + 1];
	cell_value = S3[row][col];
	rf_buffer8[4] = cell_value % 2;
	rf_buffer8[4 + 1] = cell_value / 2;

	row = rf_buffer12[9] * 2 + rf_buffer12[9 + 2];
	col = rf_buffer12[9 + 1];
	cell_value = S4[row][col];
	rf_buffer8[6] = cell_value % 2;
	rf_buffer8[6 + 1] = cell_value / 2;

	// permutation of 8 bits
	for (int i = 0; i < 8; i++)
		rf_output8[i] = rf_buffer8[P[i]];
}

// key schedule inputs are key and rounds
// output will be in rf_subkey12 and reverse_rf_subkey12 arrays
void key_schedule(int rounds)
{
	int ks_buffer14[14];
	int ks_left_half7[7];
	int ks_right_half7[7];
	int shift;
	int tmp;

	for (int j = 0; j < rounds; j++)
	{
		// permuted choice 1
		for (int i = 0; i < 14; i++)
			ks_buffer14[i] = key16[PC1[i]];

		// split to two halves
		for (int i = 0; i < 7; i++)
			ks_left_half7[i] = ks_buffer14[i];
		for (int i = 0; i < 7; i++)
			ks_right_half7[i] = ks_buffer14[i + 7];

		// bit rotate by shift no of positions
		shift = SHIFTS[j];

		for (int k = 0; k < shift; k++)
		{
			tmp = ks_left_half7[0];
			for (int i = 0; i < 6; i++)
				ks_left_half7[i] = ks_left_half7[i + 1];
			ks_left_half7[6] = tmp;

			tmp = ks_right_half7[0];
			for (int i = 0; i < 6; i++)
				ks_right_half7[i] = ks_right_half7[i + 1];
			ks_right_half7[6] = tmp;
		}

		// combine two halves
		for (int i = 0; i < 7; i++)
			ks_buffer14[i] = ks_left_half7[i];
		for (int i = 0; i < 7; i++)
			ks_buffer14[i + 7] = ks_right_half7[i];

		// permuted choice 2
		for (int i = 0; i < 12; i++)
		{
			rf_subkey12[j][i] = ks_buffer14[PC2[i]];
			reverse_rf_subkey12[rounds - j - 1][i] = ks_buffer14[PC2[i]];
		}
	}
}

// iterative cipher inputs are plaintext, number of rounds and mode
// output will be in ciphertext
void iterative_cipher(int rounds, int mode)
{
	int ic_buffer16[16];
	int ic_buffer8[8];

	// initial permutation
	for (int i = 0; i < 16; i++)
		ic_buffer16[i] = plaintext16[IP[i]];

	// split to left and right halfs
	for (int i = 0; i < 8; i++)
		left_half8[i] = ic_buffer16[i];
	for (int i = 0; i < 8; i++)
		right_half8[i] = ic_buffer16[i + 8];

	for (int j = 0; j < rounds; j++)
	{
		// now we have the right_half8 and rf_subkey setup
		// so, we can call round_function
		// the output will be in rf_output8
		round_function(j, mode);

		// xor left half and round function output
		for (int i = 0; i < 8; i++)
			ic_buffer8[i] = left_half8[i] ^ rf_output8[i];

		// copy right half to left half
		for (int i = 0; i < 8; i++)
			left_half8[i] = right_half8[i];

		// copy xor output to right_half
		for (int i = 0; i < 8; i++)
			right_half8[i] = ic_buffer8[i];
	}

	// join to left and right halfs with a switch
	for (int i = 0; i < 8; i++)
		ic_buffer16[i] = right_half8[i];
	for (int i = 0; i < 8; i++)
		ic_buffer16[i + 8] = left_half8[i];

	// final permutation
	for (int i = 0; i < 16; i++)
		ciphertext16[i] = ic_buffer16[FP[i]];
}

// insert
char *randstring(size_t length)
{

	static char charset[] = "10";
	char *randomString = NULL;

	if (length)
	{
		randomString = malloc(sizeof(char) * (length + 1));

		if (randomString)
		{
			for (int n = 0; n < length; n++)
			{
				int key = rand() % (int)(sizeof(charset) - 1);
				randomString[n] = charset[key];
			}

			randomString[length] = '\0';
		}
	}

	return randomString;
}


void main(int argc, char *argv[])
{
  int rounds = 8;
  int plaintext16org[16];
  int equal_bits;
  int unequal_bits;
  double avg_avalanche;
  double tot_avg;

  for (int i = 0; i < 1000000; i++)
  {

    // char k[16];
    // char t[16];

    // //generate random key and plaintext of length 16
    // gen_random(k, 16);
    // gen_random(t, 16);

	char* k=randstring(16);
	char* t=randstring(16);
    
    // modify
    // load key vector
    for (int i = 0; i < 16; i++)
      key16[i] = (int)k[i] - (int)'0'; //(int)argv[1][i]-(int)'0';
	
    // modify
    // load plaintext vector
    for (int i = 0; i < 16; i++)
    {
      plaintext16[i] = (int)t[i] - (int)'0'; //(int)argv[2][i]-(int)'0';
      plaintext16org[i] = plaintext16[i];
    }

    // generate key schedule
    key_schedule(rounds);
    // for (int i = 0; i < rounds; i++)
    // {
    //   printf("subkey%i ", i);
    //   for (int j = 0; j < 12; j++)
    //     printf("%i", rf_subkey12[i][j]);
    //   printf("\n");
    // }

    // printf("plain : ");
    // for (int i = 0; i < 16; i++)
    //   printf("%i", plaintext16[i]);
    // printf("\n");

    // mode 0 for encryption
    iterative_cipher(rounds, 0);

    // printf("cipher: ");
    // for (int i = 0; i < 16; i++)
    //   printf("%i", ciphertext16[i]);
    // printf("\n");

    // reload plaintext vector with cipher output
    for (int i = 0; i < 16; i++)
      plaintext16[i] = ciphertext16[i];

    // mode 1 for decryption
    iterative_cipher(rounds, 1);

    // printf("plain : ");
    // for (int i = 0; i < 16; i++)
    //   printf("%i", ciphertext16[i]);
    // printf("\n");

    // compute the avalanche value
    equal_bits = 0;
    unequal_bits = 0;
    for (int i = 0; i < 16; i++)
    {
      if (plaintext16[i] == ciphertext16[i])
        equal_bits++;
      else
        unequal_bits++;
    }
	
    // modify
    if ((equal_bits + unequal_bits) != 16)
      printf("something is terribly wrong!");
    else
      // printf("avalanche: %f\n", unequal_bits / 16.0);
      tot_avg += unequal_bits / 16.0;

    // do a sanity check for the code
    equal_bits = 0;
    unequal_bits = 0;
    for (int i = 0; i < 16; i++)
    {
      if (plaintext16org[i] == ciphertext16[i])
        equal_bits++;
      else
        unequal_bits++;
    }
    if ((equal_bits != 16) && (unequal_bits != 0))
      printf("something is terribly wrong!");
  }

  // modify
  printf("Average avalanche: %f\n", tot_avg / 1000000);
}


// Average avalanche value = 0.495976

