/*
 * Free IBM WebSphere Application Server Password Decoder v0.03
 * Copyleft - 2014  Javier Dominguez Gomez
 * Written by Javier Dominguez Gomez <jdg@member.fsf.org>
 * GnuPG Key: 6ECD1616
 * Madrid, Spain
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Compilation: gcc -std=gnu99 -Wall -c -MMD -MP -MF"fiwaspd.d" -MT"fiwaspd.d" -o "fiwaspd.o" fiwaspd.c
 *              gcc -o fiwaspd fiwaspd.o -lcrypt
 *
 * Usage:       ./fiwaspd [-v|-h]
 *
 * Examples:    ./fiwaspd
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <regex.h>
#include <unistd.h>
#include <crypt.h>

#define clear() fprintf(stdout,"\033[H\033[J\n")

static const char *title = "Free IBM WebSphere Application Server Password Decoder",*alphaNum64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char i64[256];
const float version = 0.03;

char cabecera(float),login(float),was(void),intentos(int,int),fDecodifica(char *pass);
int linea(int),fDecodificaPass(char *passEncPassword),fIniciaB64(void),fDecodificaB64(char *mi, unsigned rz, const char *k);
void siguiente(void),error(void);

int linea(int s) {
	fprintf(stdout,"+");
	for (int i = 0; i <= s; i++) {
		fprintf(stdout,"-");
	}
	fprintf(stdout,"+\n");
	return 0;
}

char cabecera(float v) {
	linea(61);
	fprintf(stdout,"| %s v%.2f |\n",title,v);
	linea(61);
	return 0;
}

char intentos(int intentos, int veces) {
	if (intentos == veces) {
		fprintf(stderr,"\n\t\tToo many tries. Exit.\n");
		exit(1);
	}
	return 0;
}

char login(float v) {
	clear();

	// User and password encrypted with encrypt.c <https://github.com/ingenieriainversa/Tools/blob/master/encrypt.c>
	const char *u = "$1$Sz/uJmtK$oNe6f04r3/WB8J0yB8y9T1"; //admin
	const char *p = "$1$C.0uJgiE$A3j2zTcyi5noAqMmep2Tp1"; //abcd1234
	const int veces = 3;
	char *U,*P;
	int i;
	cabecera(v);
	for (i = 0;i < veces;i++) {
		U = crypt(getpass("\n User:  "), u);
		if (strcmp(U,u) != 0) {
			fprintf(stderr,"\t\tWrong user\n");
			continue;
		}
		P = crypt(getpass(" Password: "), p);
		if (strcmp(P,p) != 0) {
			fprintf(stderr,"\n\t\tWrong password\n");
			continue;
		}
		break;
	}
	intentos(i,veces);
	return 0;
}

int fIniciaB64(void) {
	int i;
	const char *p;
	for (i = 0;i < 256;i++) {
		i64[i] = -1;
	}
	for (p = alphaNum64,i = 0;*p; p++,i++) {
		i64[(int) *p] = i;
	}
	i64['='] = 0;
	return 0;
}

int fDecodificaB64(char *mi,unsigned rz,const char *k) {
	unsigned p = 0,val,xo = 0;
	int i;
	while (*k) {
		for (val = 0;val < 4;val++) {
			if (!*k) {
				break;
			}
			i = i64[(int) *k++];
			if (i < 0) {
				return (-1);
			}
			p <<= 6;
			p |= i;
		}
		for (val = 0;val < 3;val++) {
			if (xo >= rz - 1) {
				return (-1);
			}
			*mi = (p >> 16) & 0xff;
			p <<= 8;
			xo++;
			mi++;
		}
	}
	*mi = '\0';
	return(0);
}

int fDecodificaPass(char *passEncPassword) {
	char *pass,passEnc[1024];
	pass = strchr(passEncPassword, '}');
	if (pass) {
		++pass;
	} else {
		pass = passEncPassword;
	}
	strtok(pass,"\"");
	fDecodificaB64(passEnc,sizeof passEnc,pass);
	pass = passEnc;
	fDecodifica(pass);
	fprintf(stdout,"\n\n");
	return pass - passEnc;
}

char fDecodifica(char *pass) {
	while (*pass && (*pass != '\"')) {
		putc(*pass++ ^ '_',stdout);
	}
	return *pass;
}

void siguiente(void) {
	int ch;
	while ((ch = getchar()) != '\n' && ch != EOF) {
		fprintf(stdout,"\n\tPress INTRO to continue.");
	}
	while ((ch = getchar()) != '\n' && ch != EOF) {
		return;
	}
}

void error(void) {
	clear();
	fprintf(stderr,"\n\tWARNING: Invalid option");
	siguiente();
}

char was(void) {
	const int veces = 3;
	int i;
	char string[2048];
	clear();
	cabecera(version);
	for (i = 0;i < veces;i++) {
		fprintf(stdout,"\n Encrypted password:\t");
		fgets(string,2048,stdin);
		if (strstr(string,"{xor}") == NULL) {
			fprintf(stderr,"\t\tWrong password format [{xor}XXXXX...]\n");
			continue;
		}
		break;
	}
	intentos(i,veces);

	fflush(stdin);
	fIniciaB64();
	fprintf(stdout," Decrypted password:\t");
	fDecodificaPass(string);
	return 0;
}

char uso(char *bin){
	fprintf(stdout,"\tUsage:\t\t%s [-v|-h]\n",bin);
	return 0;
}

int main(int argc,char *argv[]) {
	opterr = 0;
	int c,stdOut = '\0';
	while ((c = getopt(argc,argv,"vh")) != -1) {
		switch (c) {
			case 'v':
				fprintf(stdout,"%1.2f\n",version);
				return 0;
				break;
			case 'h':
				fprintf(stdout,"\n   HELP\n\n\tDescription:\t%s v%1.2f\n\n",title,version);
								uso(argv[0]);
				fprintf(stdout,"\n\tOptions:\t-v\tSoftware version.\n"
								"\t\t\t-h\tThis help.\n\n");
				return 0;
				break;
			case '?':
				if (isprint(optopt))
					fprintf(stderr,"Unknow option '-%c'.\n", optopt);
				else
					fprintf(stderr,"Unknow char '\\x%x'.\n", optopt);
				return 1;
			default:
				abort();
		}
	}

	// Autentication [coment this line if you want to disable security]
	stdOut = login(version);

	if (!stdOut) {
		was();
	}
}
