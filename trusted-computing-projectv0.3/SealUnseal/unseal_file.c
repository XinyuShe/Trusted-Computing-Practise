/**
 * @file seal_file.c
 * @author WangFengwei Email: 110.visual@gmail.com
 * @brief seal a file
 * @created 2011-06-19
 * @modified
 */

#include "common.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx)
{
  int i, nrounds = 5;
  unsigned char key[32], iv[32];
  
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_DecryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  EVP_DecryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  /* update ciphertext with the final remaining bytes */
  EVP_DecryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

void 
usage(char *pch_name)
{
	printf("Usage: %s source destination\n", pch_name);
	printf("eg: %s plaintext_file cipertext_file\n", pch_name);
}

int 
main(int argc, char **argv)
{

#define BUF_LEN	(1024*1024)
#define KEY_SIZE 64
	TSS_RESULT result;
	TSS_HCONTEXT hContext;
	TSS_HKEY hSRK, hKey;
	TSS_HPOLICY hPolicy;
	TSS_HTPM hTPM;
	TSS_HENCDATA hEncData;
	TSS_HPCRS hPcrs;
	UINT32 u32PcrValLen, u32EncDataLen;
	BYTE *rgbPcrVal, *rgbEncData;
	
	UINT32 randomLen;
	BYTE *random;
	
	FILE *fpIn = NULL, *fpOut = NULL;
	int len, size;
	char *pBufIn = NULL, *pBufOut = NULL;
	unsigned int salt[] = {12345, 54321};
	EVP_CIPHER_CTX en;
	TSS_UUID UUID_K1 =  {0, 0, 0, 0, 0, {8, 0, 0, 0, 0, 1}} ;

	if (argc < 3) {
		usage(argv[0]);
		return 0;
	}

	result = Tspi_Context_Create(&hContext);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_Create", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_Connect", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_GetTpmObject", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = Tspi_Context_LoadKeyByUUID(hContext, 
					TSS_PS_TYPE_SYSTEM, 
					SRK_UUID, 
					&hSRK);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		Tspi_Context_Close(hContext);
		return result;
	}

#ifndef TESTSUITE_NOAUTH_SRK
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hPolicy);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_GetPolicyObject", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = Tspi_Policy_SetSecret(hPolicy, 
						TESTSUITE_SRK_SECRET_MODE, 
						TESTSUITE_SRK_SECRET_LEN, 
						TESTSUITE_SRK_SECRET);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Policy_SetSecret", result);
		Tspi_Context_Close(hContext);
		return result;
	}
#endif // #ifndef TESTSUITE_NOAUTH_SRK

	result = Tspi_Context_CreateObject(hContext, 
						TSS_OBJECT_TYPE_PCRS, 
						0, 
						&hPcrs);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = Tspi_Context_CreateObject(hContext, 
						TSS_OBJECT_TYPE_ENCDATA, 
						TSS_ENCDATA_SEAL, 
						&hEncData);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = set_secret(hContext, hEncData, &hPolicy);
	if (TSS_SUCCESS != result) {
		print_error("set_secret", result);
		Tspi_Context_Close(hContext);
		return result;
	}						

	result = Tspi_Context_LoadKeyByUUID(hContext, 
						TSS_PS_TYPE_SYSTEM, 
						UUID_K1, 
						&hKey);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		Tspi_Context_Close(hContext);
		return -1;
	}

	result = set_popup_secret(hContext, 
						hKey, 
						TSS_POLICY_USAGE, 
						"Input K1's Pin\n", 
						0);
	if (TSS_SUCCESS != result) {
		print_error("set_popup_secret", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	/*result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hPolicy);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_GetPolicyObject", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = Tspi_Policy_SetSecret(hPolicy, 
						TESTSUITE_KEY_SECRET_MODE, 
						TESTSUITE_KEY_SECRET_LEN, 
						TESTSUITE_KEY_SECRET);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Policy_SetSecret", result);
		Tspi_Context_Close(hContext);
		return result;
	}*/

	////result = Tspi_TPM_GetRandom(hTPM, KEY_SIZE, &random);
	////if (TSS_SUCCESS != result) {
	////	print_error("Tspi_TPM_GetRandom", result);
	////	Tspi_Context_Close(hContext);
	////	return result;
	////}

	result = Tspi_TPM_PcrRead(hTPM, 15, &u32PcrValLen, &rgbPcrVal);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_TPM_PcrRead", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = Tspi_PcrComposite_SetPcrValue(hPcrs, 15, u32PcrValLen, rgbPcrVal);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_PcrComposite_SetPcrValue", result);
		Tspi_Context_Close(hContext);
		return result;
	}



	fpIn = fopen(argv[1], "rb");
	if (!fpIn) {
		printf("open file: %s failed\n", argv[1]);
		Tspi_Context_Close(hContext);
		return result;
	}

	fseek(fpIn, 0, SEEK_END);
	size = ftell(fpIn);

	if (size > BUF_LEN) {
		printf("file is more than 1MB, too big !\n");
		Tspi_Context_Close(hContext);
		fclose(fpIn);
		return -1;
	}


	fseek(fpIn, 0, SEEK_SET);
	
	
////
	len = fread(&u32EncDataLen, 1, sizeof(UINT32), fpIn);
	if (sizeof(UINT32) != len) {
		printf("fread u32EncDataLen failed\n");
		Tspi_Context_Close(hContext);
		free(pBufIn);
		fclose(fpIn);
		return -1;
	}
//printf("1\n 1");
	rgbEncData = malloc(u32EncDataLen);
	if (!rgbEncData) {
		printf("No Memmory\n");
		Tspi_Context_Close(hContext);
	}
	len = fread(rgbEncData, 1, u32EncDataLen, fpIn);
	if (len != u32EncDataLen) {
		printf("fread rgbEncData failed\n");
		Tspi_Context_Close(hContext);
		free(pBufIn);
		fclose(fpIn);
		return -1;
	}

	len = fread(&size, 1, sizeof(int), fpIn);
	if (len != sizeof(int)) {
		printf("fread failed\n");
		Tspi_Context_Close(hContext);
		free(pBufIn);
		fclose(fpIn);
		return -1;
	}
	
	pBufIn = malloc(size);
	if (!pBufIn) {
		printf("No Memmory\n");
		Tspi_Context_Close(hContext);
	}
	len = fread(pBufIn, 1, size, fpIn);
	if (len != size) {
		printf("fread failed\n");
		Tspi_Context_Close(hContext);
		free(pBufIn);
		fclose(fpIn);
		return -1;
	}
////
	fclose(fpIn);
	
////TODO
	result = Tspi_SetAttribData(hEncData, 
						TSS_TSPATTRIB_ENCDATA_BLOB, 
						TSS_TSPATTRIB_ENCDATABLOB_BLOB, 
						u32EncDataLen, 
						rgbEncData);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_SetAttribData", result);
		Tspi_Context_Close(hContext);
		return result;
	}
	//print_hex(rgbEncData,u32EncDataLen);
	result = Tspi_Data_Unseal(hEncData, 
					hKey, 
					&randomLen,
					&random);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Data_UnSeal", result);
		Tspi_Context_Close(hContext);
		return result;
	}
	
	//printf("Unsealed Data:\n");
	//print_hex(random, randomLen);
	



	if (aes_init(random, KEY_SIZE, (unsigned char *)&salt, &en)) {
		printf("aes_init failed\n");
		Tspi_Context_Close(hContext);
		free(pBufIn);
		return -1;
	}

	pBufOut = aes_decrypt(&en, pBufIn, &size);


	fpOut = fopen(argv[2], "wb");
	if (!fpOut) {
		printf("open file: %s failed\n", argv[2]);
		Tspi_Context_Close(hContext);
		free(pBufIn);
		free(pBufOut);
		return -1;
	}

	len = fwrite(pBufOut, 1, size, fpOut);
	if (size != len) {
		printf("fwrite pBufOut failed\n");
		Tspi_Context_Close(hContext);
		free(pBufIn);
		free(pBufOut);
		fclose(fpOut);
		return -1;
	}
	fclose(fpOut);
	
	//printf("%s\n",pBufOut);

	
	free(pBufIn);
	free(pBufOut);

	Tspi_Context_Close(hContext);

	return 0;
	
}
