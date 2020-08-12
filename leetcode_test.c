#include <stdio.h>
#include <string.h>
/**
 *@brief: this function count the binary string which has the same group
 *@input: a string s
 *@output:the number of the same group
 *like 
 * */
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

/**
 *@brief : find the longest substring that does not contain repeated chararcters from the string, and calculate the length of the longest sunstring.
 *@input : the string
 *@output: the length of the longest sunstring
 * */

int lengthOfLongestSubstring(char*s){
	if(s==NULL)return 0;
	if(strlen(s)==1)return 1;
	int arr[128] = {0}, index=0;max=0,i;
	for(i=0;i<strlen(s);i++){
		if(arr[s[i]] == 0){
			//no repeat word
			arr[s[i]] = 1;
		}else{
			//there has the repeat word, and the repeat word is s[i]
			if((i-index)>max)max = i- index;
			for(;index<i;i++){
				if(s[index] == s[i]){
					index ++;
					break;
				}else{//clear the word recording without repeated
					arr[s[index]] = 0;
				}
			}
			
		}

	}
	//if the string without repeated word this code will calculate the max length
	if((i-index)>max)max = i-index;
	return max;
}
