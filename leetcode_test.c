#include <stdio.h>
#include <string.h>

int countBinarySubstirngs(char *s){
	int n=0,pre=0,curr=1,len=strlen(s)-1;
	for(int i=0;i<len;i++){
		if(s[i] == s[i+1]) ++curr;
		else{
			pre = curr;
			curr=1;
		}
		if(pre >= curr) ++n;
	}
	return n;
}
