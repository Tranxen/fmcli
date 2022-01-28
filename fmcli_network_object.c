#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include "global.h"

//#include <jansson.h>
//#include <curses.h>
//#include <menu.h>

#define BUFFER_SIZE (256 * 1024) /* 256 KB */
#define BASE_URL_MAX_SIZE 2048
#define LABEL_MAX_SIZE 1024
#define FILENAME_MAX_SIZE 128

#define FMC_MAX_NAME_SIZE 64

#define CTRLD 	4

char error_filename[] = "UNKNOWN";
char g_str_access_token[128];
unsigned char g_flag=1;

#define CL_TOKEN 0
#define CL_POST 1
#define CL_GET 2

#define TYPE_NONE 0
#define TYPE_HOST 1
#define TYPE_NET 2
#define TYPE_RANGE 3
#define TYPE_FQDN 4

#define FLAG_RESOLV_IP 1


/* Return the offset of the first newline in text or the length of
   text if there's no newline */
static int newline_offset(const char *text) {
    const char *newline = strchr(text, '\n');
    if (!newline)
         return strlen(text);
    else
        return (int)(newline - text);
}
 
struct write_result {
  char *data;
  int pos;
};
 
static size_t header_callback(char *buffer, size_t size,
                              size_t nitems, void *userdata)
{
  /* received header is nitems * size long in 'buffer' NOT ZERO TERMINATED */
  /* 'userdata' is set with CURLOPT_HEADERDATA */
  //printf("header_callback...\n");
  
  //X-auth-access-token:
  if(nitems >= 20){
    if(buffer[0] == 'X' && buffer[1] == '-' && buffer[2] == 'a' && buffer[7] == 'a' && buffer[19] == ':'){

      int i = 0;
      memset(g_str_access_token, '\0', 128);
      strncpy(g_str_access_token, buffer, nitems-2);

      //for(i=0 ; i < nitems; i++){
      //printf("%c:%2X\n", buffer[i], buffer[i]);
      //}
      
      printf("g_str_access_token : %s\n", g_str_access_token);
      FILE* fd = fopen("/tmp/token.cache","w");
      if(fd){
	fwrite(g_str_access_token, sizeof(char), nitems, fd);
	fclose(fd);
      }

    }   
  }
  
  return nitems * size;
}


static size_t write_response(void *ptr, size_t size, size_t nmemb, void *stream) {
    struct write_result *result = (struct write_result *)stream;

    if (result->pos + size * nmemb >= BUFFER_SIZE - 1) {
        fprintf(stderr, "error: too small buffer\n");
        return 0;
    }

    memcpy(result->data + result->pos, ptr, size * nmemb);
    result->pos += size * nmemb;

    return size * nmemb;
}

static char *request(const char *url, const char* postdata, unsigned char flag) {
    CURL *curl = NULL;
    CURLcode status;
    struct curl_slist *headers = NULL;
    char *data = NULL;
    long code;
    char dummy[] = "DUMMY";

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl)
        goto error;

    data = malloc(BUFFER_SIZE);
    if (!data)
        goto error;

    struct write_result write_result = {.data = data, .pos = 0};

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if(flag == CL_POST || flag == CL_GET){
      headers = curl_slist_append(headers, "Accept: application/json");
      headers = curl_slist_append(headers, g_str_access_token);
      int i = 0;
    }

    if(flag == CL_TOKEN){
      curl_easy_setopt(curl, CURLOPT_USERPWD, "<USER>:<PASSWORD>");
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(dummy));
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, dummy);
      curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION,header_callback);
    }

    if(flag == CL_POST){
      //printf("postdata (%ld) = %s\n",  (long) strlen(postdata), postdata);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(postdata));
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_URL, url);
  
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_result);

    status = curl_easy_perform(curl);

    if (status != 0) {
        fprintf(stderr, "error: unable to request data from %s:\n", url);
        fprintf(stderr, "%s\n", curl_easy_strerror(status));
        goto error;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    printf("HTTP Reply Code : %ld\n", code);

    /* zero-terminate the result */
    data[write_result.pos] = '\0';

    if(flag == CL_TOKEN){
      if (code != 204){
	fprintf(stderr, "error: server responded with code %ld\n", code);	
	fprintf(stderr, "error info : token might not be requested\n");
      }
    }

    if(flag == CL_GET){
      if (code != 200) {
         fprintf(stderr, "error: server responded with code %ld\n", code);
	fprintf(stderr, "error info (get) : %s\n", data);
        goto error;
      } 
    }

    if(flag == CL_POST){
      if (code != 201) {
        fprintf(stderr, "error: server responded with code %ld\n", code);
	fprintf(stderr, "error info (post) : %s\n", data);
      }
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    curl_global_cleanup();

    return data;

error:
    if (data)
        free(data);
    if (curl)
        curl_easy_cleanup(curl);
    if (headers)
        curl_slist_free_all(headers);
    curl_global_cleanup();
    return NULL;
}


void check_ip_addr(char* ip){

  int i = 0;
  for(i = 0; i < strlen(ip); i++){
    if((ip[i] < '0' || ip[i] > '9') && ip[i] != '.'){
      printf("Error : %s is not an IP address\n", ip);
      exit(-1);
    }
  }

}

void check_ciddr_mask(char* mask){

  int i = 0;
  for(i = 0; i < strlen(mask); i++){
    if(mask[i] < '0' || mask[i] > '9'){
      printf("Error : %s is not an CIDDR mask address\n", mask);
      exit(-1);
    }
  }

  int _mask = atoi(mask);

  if(_mask < 0 || _mask > 32){
    printf("Error : %d is not an CIDDR mask address\n", _mask);
    exit(-1);
  }
  
}

int get_name_from_ip(char* ip, char* name){

  struct sockaddr_in sa;    /* input */
  socklen_t len;         /* input */
  char hbuf[NI_MAXHOST];

  memset(hbuf, '\0', NI_MAXHOST);
  memset(&sa, 0, sizeof(struct sockaddr_in));

  /* For IPv4*/
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = inet_addr(ip);
  len = sizeof(struct sockaddr_in);

  if (getnameinfo((struct sockaddr *) &sa, len, hbuf, sizeof(hbuf),
		  NULL, 0, NI_NAMEREQD)) {
    printf("could not resolve hostname (%s)\n", ip);
    return 0;
  }
  else {
    printf("host=%s\n", hbuf);
    int i = 0;
    for(i=0; i < 32 && hbuf[i]!='.' && hbuf[i]!='\0';i++){
      name[i]=hbuf[i];
    }
    return 1;
  }


}

int get_network_type(char* type, char* defaultname, char* ip){

  char* slash = strchr(ip, '/');
  char* dash = strchr(ip, '-');

  char* _ip_ = ip;
  char* _mask_ = NULL;

  if(slash){

    if(ip[0]=='.'){
      printf("ERROR : get_network_type() : you cannot resolv a subnet !\nPlease remove the . prefixing the subnet\n\n");
      exit(-1);
    }

    _mask_ = slash+1;
    *slash = '\0';
    _ip_=ip;
    check_ip_addr(_ip_);
    check_ciddr_mask(_mask_);
    // set default name
    
    strncpy(defaultname, "G_net-", 6);
    strncat(defaultname, _ip_, 16);
    strncat(defaultname, "-", 1);
    strncat(defaultname, _mask_, 2);
    // set type 
    strncpy(type, "network", 7);

   // set back network
    *slash='/';
    printf("get_network_type : network : %s\n", ip);
  }
  else{
    
    char resolv_ip = 0;

    if(ip[0] == '.'){
      resolv_ip = 1;
      ip=ip+1;
    }

    check_ip_addr(ip);
    printf("get_network_type : host : %s\n", ip);
    // set type
    strncpy(type, "host", 4);
    // set default name
    strncpy(defaultname, "G_srv-", 6);
    if(resolv_ip){
      char rname[FMC_MAX_NAME_SIZE];memset(rname, '\0', FMC_MAX_NAME_SIZE);
      if(get_name_from_ip(ip, rname)){
	strncat(defaultname, rname, 32);
      }
      else{
	strncat(defaultname, ip, 16);
      }
    }
    else{
      strncat(defaultname, ip, 16);
    }
  }

}

void add_network_object(char* ip, char* name, char* desc, unsigned char flag){

  //"{\"name\": \"TestHost\", \"type\": \"Host\", \"valu\e\": \"10.5.3.20\"}";

  char _type_[16]; memset(_type_, '\0', 16);
  char default_name[FMC_MAX_NAME_SIZE]; memset(default_name, '\0', FMC_MAX_NAME_SIZE);

  get_network_type(_type_, default_name, ip);

  char* _name_;
  if(name){
    _name_ = name;
  }
  else{
    _name_ = default_name;
  }
   
  char postdata[256];
  
  char str_name[]="{\"name\": \"";
  char str_type[]="\", \"type\": \"";
  char str_value[]="\", \"value\": \"";
  char str_end[]="\"}";

  strncpy(postdata, str_name, 16);
  strncat(postdata, _name_, FMC_MAX_NAME_SIZE);
  strncat(postdata, str_type, 16);
  strncat(postdata, _type_, 16);
  strncat(postdata, str_value, 16);
  strncat(postdata, ip, 32);
  strncat(postdata, str_end, 4);

  printf("P:%s\n", postdata);

  char url_base[1024];
  strncpy(url_base, "https://<URL>/api/fmc_config/v1/domain/<DOMAIN>/object/", 256);
  
  strncat(url_base, _type_, 16);
  strncat(url_base, "s", 1);

  printf("U:%s\n", url_base);

  char* text = request(url_base, postdata, CL_POST);

  printf("--\n");
  if(text)
    printf("%s\n", text);

}

void add_group_object(char* data, char* description){
  
  char groupname[FMC_MAX_NAME_SIZE]; memset(groupname, '\0', FMC_MAX_NAME_SIZE);

  char* slash = strchr(data, '/');
  char* equal = strchr(data, '=');
  char* dash = strchr(data, '-');  

  if(!equal){
    printf("ERROR : add_group_object : wrong synthax\n");
    printf("        Correct synthax is GroupName=Object1,Object2,ObjectN\n");
    exit(-1);
  }
  
  int p=0;
  for(p=0; data[p] != '='; p++){
    groupname[p]=data[p];
  }
  data+=p+1;

  const char s[2] = ",";
  char *token;
   
  /* get the first token */
  token = strtok(data, s);

  char postdata[4096];memset(postdata, '\0', 4096);

  strncpy(postdata, "{\"name\": \"", 16);
  strncat(postdata, groupname, FMC_MAX_NAME_SIZE);
  strncat(postdata, "\",\"literals\":[", 20);

  /* walk through other tokens */
  while( token != NULL ) {

    char _type_[16]; memset(_type_, '\0', 16);
    char default_name[FMC_MAX_NAME_SIZE]; memset(default_name, '\0', FMC_MAX_NAME_SIZE);

    get_network_type(_type_, default_name, token);
    printf( " %s - %s - %s\n", token, _type_, default_name);

    strncat(postdata, "{\"type\": \"", 16);
    strncat(postdata, _type_, 8);
    strncat(postdata, "\",\"value\": \"", 16);
    strncat(postdata, token, 32);
    strncat(postdata, "\"},", 4);
        
    token = strtok(NULL, s);
  }
  
  //remove last colon.
  
  postdata[strlen(postdata)-1]='\0';
  strncat(postdata, "],\"type\": \"NetworkGroup\"}", 32);

  printf("P:%s\n", postdata);

  char url_base[1024];
  strncpy(url_base, "https://<FMC_IP_ADDRESS>/api/fmc_config/v1/domain/DOMAIN/object/networkgroups", 256);

  printf("U:%s\n", url_base);

  char* text = request(url_base, postdata, CL_POST);

  printf("--\n");
  if(text)
    printf("%s\n", text);

}

void add_port_object(char* ip, char* name, char *desc, unsigned char flag){

  /*

    TODO

  {
    "name": "protocolport_obj1",
    "protocol": "TCP",
    "port": 123,
    "type": "ProtocolPortObject"
   }
  */

}

int main(int argc, char** argv)
{

  char *text;

  char *opt_ip = NULL;
  char *opt_name = NULL;
  char *opt_desc = NULL;
  
  char *opt_port = NULL;

  unsigned char flag_i = 0;
  unsigned char flag_n = 0;
  unsigned char flag_d = 0;
  unsigned char flag_G = 0;

  unsigned char flag_p = 0;

  unsigned char flag_f = 0;

  int index;
  int c;

  opterr = 0;

  while ((c = getopt (argc, argv, "G:i:n:d:h")) != -1){
    switch (c)
      {
      case 'i':
        flag_i=1;
        opt_ip=optarg;
        break;
      case 'G':
	flag_G=1;
	opt_ip=optarg;
      case 'n':
	flag_n=1;
	opt_name=optarg;
        break;
      case 'd':
        flag_d=1;
        opt_desc=optarg;
        break;
      case 'h':
        printf("========= QUICKFMC HELP =========\n\n");
	printf(" One of the following option is mandatory\n");
	printf("   -i <IP address> : Add network object (host or network)\n");
	printf("   -s <Protocol/Port>: Add service object\n");
	printf("   -f <FQDN>: Add network FQDN\n");
	printf("   -G <GROUPNAME>=<IP1>,<IP2>,<IPx>\n");
	printf("\n The rest\n");
	printf("   -n <name> : Set object name\n");
	printf("   -d <description> : Set object description\n");
	printf("\n");
        return 0;
      case '?':
        if (optopt == 'i' || optopt == 'n' || optopt == 'd' || optopt == 'G')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr,
                   "[err] Unknown option character `\\x%x'.\n",
                   optopt);
        return 1;
      default:
        abort ();

      }
  }

  if(flag_i == 0 && flag_p == 0 && flag_f == 0 && flag_G == 0){
    printf("you get the option wrong idiot ! You need to use either -i or -s or -f or -G\n\n");
    return -1;
  }

  if((flag_i + flag_G + flag_f + flag_p) > 1){
    printf("you need to use either -i or -s or -f or -G, you cannot use multiple at the same time\n\n");
    return -1;
  }

  //=========== GET TOKEN ===========

  FILE* fd = fopen("/tmp/token.cache","r");
  if(fd){
    struct stat sb;
    if (lstat("/tmp/token.cache", &sb) == -1) {
      perror("lstat");
      exit(EXIT_FAILURE);
    }
    
    time_t rawtime_now;
    time (&rawtime_now);


    if((rawtime_now - sb.st_mtime) > 1500){
      printf("* token cache is too old...\n");
      fclose(fd);
      fd=NULL;
    }
    else{
      printf("* using cache for auth token\n");
      fread(g_str_access_token, sizeof(char), 128, fd);
      fclose(fd);
    }

  }

  if(!fd){
    printf("* requesting new auth token\n");
    const char *url = "https://<FMC_IP_ADDRESS>/api/fmc_platform/v1/auth/generatetoken";
    text = request(url, NULL, CL_TOKEN);
  }
  printf("  - %s\n\n", g_str_access_token);


  if(flag_i){
    add_network_object(opt_ip, opt_name, NULL, 0);
  }

  if(flag_G){
    add_group_object(opt_ip, NULL);
  }


  return 0;

}

  
    
