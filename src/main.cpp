/*  Sample to connect to DPS and provision a device through Group Enrollment 
  Group enrollment serves to provision various devices in one go, every device with
  the exact same firmware or code. 
  1 - This is done by using the Group Enrollment's Master Key, which was created 
  when the Group Enrollment Entry was set in the DPS with the Azure Portal.
  2 - Then, for each device we want to enroll, we create a unique identifier,
  for example its MAC.
  3 - With the Master Key we HMAC-SHA256 hash the device id.
  4 - We are then capable of connecting to the DPS using.
            char *dps_server = "global.azure-devices-provisioning.net";
            const char *dps_user = "{idScope}/registrations/{groups_registration_id}/api-version=2019-03-31";
            char *dps_url = "{idScope}/registrations/{groups_registration_id}";

    We also have the prymary DPS owner connection string
    "HostName=DPS-QST.azure-devices-provisioning.net;SharedAccessKeyName=provisioningserviceowner;SharedAccessKey=n1UzLRPJnQYvDfC1tN6lF+rcY6s/7aV5yFZeP3JLZBk="
*/
#define TINY_GSM_MODEM_SIM7000SSL
#include <Arduino.h>
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include "time.h"
#include "sha256.h"
#include "Base64.h"
#include "Utils.h"
#include <ArduinoJson.h>
#include <mbedtls/md.h>
#include <TinyGSM.h>
#include "SD.h"

#define SerialAT Serial2
#define GPRS_DEBUG  0
#define SERIAL_DEBUG  1
#define MQTT_DEBUG  1
#define DPS_RETRIES 10

uint8_t fails_dps=0;
char* provision = "/provision.txt";

WiFiClientSecure wifi_client;

char const *wifi_ssid = "XXXXX";
char const *wifi_password = "XXXXX";
// Secure ssl port
const int port = 8883;

/*GPRS CONFIG*/
char* apn = "igprs.claro.com.ar"; //Claro
//char* apn = "wap.gprs.unifon.com.ar"; //Movistar
char* gprsUser = "";
char* gprsPass = "";

#if GPRS_DEBUG
TinyGsm modem(SerialAT);
TinyGsmClientSecure gprsClient(modem);
PubSubClient mqtt_client(gprsClient);
PubSubClient mqtt_client2(gprsClient);
#else
PubSubClient mqtt_client(wifi_client);
PubSubClient mqtt_client2(wifi_client);
#endif

// Credentials for connecting to Hub, field within {} are provisioned by DPS
char enc_dev_key[44];
char mqtt_hub_user[150];
char mqtt_device_id[20];
String hub_sas_token_str; // generated SAS token will be used as mqtt password
char hub_sas_token[150];
char hub_url[150]; // server for mqtt connection
// Hub built-in device independent endpoint to subscribe to
char hub_sub_endpoint[150];
// Hub built-in device independent endpoint to publish to
char hub_pub_endpoint[150];

// Credentials to connect to DPS
char *dps_connect_url = "global.azure-devices-provisioning.net";
// MQTT user to connect to DPS based on the DPS registration-id and the DPS's ID Scope
// {idScope}/registrations/{registration_id}/api-version=2019-03-31
char dps_user[200];
// Use group's reg id as mqtt user id
char mqtt_dps_id[300];
char device_reg_id[18];
// URL to generate SasToken to DPS {idScope}/registrations/{registration_id}
char dps_url_sas[300];
String dps_url_sas_str;
char dps_sas_token_ch[200];
String dps_sas_token_str;
// Group Key to derive individual ones using an HMAC-SHA256 hash
char *dps_group_key = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
//DPS id scope, change between different DPS
String scope = "XXXXX";
// Topic to subscribe to and receive Hub credentials from DPS
char *dps_sub_endpoint = "$dps/registrations/res/#";
// Topic to publish to and ask for Hub's credentials to the DPS
// $dps/registrations/PUT/iotdps-register/?$rid={request_id}  request_id an integer of our choise
char *dps_pub_endpoint = "$dps/registrations/PUT/iotdps-register/?$rid=1";
// Topic to publish to asking for the state of the asignment process, request_id an integer of our choise and operationId is retrieved in steps before
// "$dps/registrations/GET/iotdps-get-operationstatus/?$rid={request_id}&operationId={operationId}"
char dps_ask_assignment[300] = "$dps/registrations/GET/iotdps-get-operationstatus/?$rid=2&operationId={operationId}";
// Form of request {“registrationId”:”<registration id>”}
char json_request[50] = "{\"registrationId\":\"{device-id}\"}";
                        
bool req_sent = false;
const char* operation_id = NULL;
const char* status = NULL;
bool dps_req_ack = false;
uint64_t instant_ask = 0;
uint64_t ask_period = 3000;
uint64_t instant_pub = 0;
uint64_t pub_period = 5000;
bool dps_assigned = false;
char hub[100];
char device_id[100];
char *device_key = "";
bool  is_dps=true;
bool a = false;

bool getHubProvisioning();
bool connectHub();
void hubCallback(char *topic, byte *payload, unsigned int length);
void hashMasterKey(const char *master_key, const char *device_reg_id, char* enc_dev_key);
void dpsCallback(char *topic, byte *payload, unsigned int length);
String createIotHubSASToken(char *key, String url, unsigned long expire);

bool getHubProvisioning()
{
  mqtt_client.setServer(dps_connect_url, port);
  mqtt_client.setCallback(dpsCallback);

  // Use MAC address as device's registration ID
  String mac = WiFi.macAddress();
  mac.replace(':','-');
  mac.toCharArray(device_reg_id, 18);

  // Build json request to ask for provisioning  
  for(uint8_t i=0; i<18;i++)
  {
    json_request[19+i] = device_reg_id[i];
  }
  json_request[36] = '"';
  json_request[37] = '}';
  json_request[38] = '\0';
  
  // Build credential to connect to DPS broker  
  String dps_user_str = scope + "/registrations/" + String(device_reg_id) + "/api-version=2019-03-31";
  dps_user_str.toCharArray(dps_user,200);
  String dps_url_sas_str = scope + "/registrations/" + String(device_reg_id);
  dps_url_sas_str.toCharArray(dps_url_sas,300);

  // Hash device's reg_id to derive device's unique key   
  hashMasterKey(dps_group_key, device_reg_id, enc_dev_key);
  device_key = enc_dev_key;
  
  // Create SAS token using device's unique key
  dps_url_sas_str = String(dps_url_sas);
  dps_sas_token_str = createIotHubSASToken(device_key, dps_url_sas_str, 0);
  is_dps=false;
  dps_sas_token_str.toCharArray(dps_sas_token_ch, 200);

  #if SERIAL_DEBUG && MQTT_DEBUG
  Serial.println("------------Device reg Id: " + String(device_reg_id));
  Serial.println("------------Prov req: " + String(json_request));
  Serial.println("------------Dps mqtt user: " + dps_user_str);
  Serial.println("------------Dev u. key: " + String(device_key));
  Serial.println("------------Dps sas token: " + String(dps_sas_token_ch));
  delay(2000);
  #endif

  while(!dps_assigned)
  {
#if SERIAL_DEBUG && MQTT_DEBUG
    Serial.println("------------No DPS loop------------");
    delay(1000);
#endif
    if(mqtt_client.connected())
    {// Have we already sent a request for provisioning?
      if (!req_sent)
      {
#if SERIAL_DEBUG && MQTT_DEBUG
        Serial.println("-----------Request published-----------");
#endif
        mqtt_client.publish(dps_pub_endpoint, json_request);
        req_sent = true;
      }
      if (dps_req_ack) // Have we received a response to our petition?
      {
        if(millis()-instant_ask>ask_period && !dps_assigned)
        {
          instant_ask=millis();
          Serial.println("------------Ask status------------");
          Serial.println(dps_ask_assignment);
          mqtt_client.publish(dps_ask_assignment,""); //Ya llegamos a la India?
        }
        if(fails_dps > DPS_RETRIES)
        {
          
        }
      }
      mqtt_client.loop();
    }
    else if(mqtt_client.connect(device_reg_id, dps_user, dps_sas_token_ch))
    {
#if SERIAL_DEBUG && MQTT_DEBUG
      Serial.println("Connecting to DPS");
      Serial.println("Connected to DPS");
#endif
      if(mqtt_client.subscribe(dps_sub_endpoint, 1))
      {
#if SERIAL_DEBUG && MQTT_DEBUG
        Serial.println("Connected to DPS and subscribed");
#endif
      }
    }
    else
    {
      Serial.println("failed to connect to DPS");
    }
  }
  return true;
}

void hashMasterKey(const char *master_key, const char *device_reg_id, char* enc_dev_key)
{
  char dec_master_key[200];
  base64_decode(dec_master_key, (char*)master_key, strlen(master_key));
  char hmac_dev_key[32]; 
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256; 
  const size_t payloadLength = strlen(device_reg_id);
  const size_t keyLength = strlen(dec_master_key);
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *) dec_master_key, keyLength);
  mbedtls_md_hmac_update(&ctx, (const unsigned char *) device_reg_id, payloadLength);
  mbedtls_md_hmac_finish(&ctx, (byte *)hmac_dev_key);
  mbedtls_md_free(&ctx);
  // START: Get base64 of signature
  base64_encode(enc_dev_key, hmac_dev_key, HASH_LENGTH);
  Serial.println(enc_dev_key);
  return;
}

void hubCallback(char *topic, byte *payload, unsigned int length)
{
  uint16_t i = 0;
  char array[1000];
  Serial.println(topic);
  for (i = 0; i < length; i++)
  {
    array[i] = (char)payload[i];
  }  
  Serial.println(array);
}

String createIotHubSASToken(char *key, String url, unsigned long expire)
{
  /*
    expiry: How long until the token expires.
      Seconds since start-up + expiry in seconds
                      + seconds since epoch 00:00hs 01/01/1970 to 00:00hs 27/05/2021 (1,621,036,800)
      Defaults to 10 years, 315.360.000 seconds in 5 years
  */
  if (expire == 0)
    expire = 1621036800 + 315360000 + millis() * 1000; //hardcoded expire

  url.toLowerCase();

  String stringToSign = url + "\n" + String(expire);
  // START: Create signature
  // https://raw.githubusercontent.com/adamvr/arduino-base64/master/examples/base64/base64.ino
  int keyLength = strlen(key);

  int decodedKeyLength = base64_dec_len(key, keyLength);
  char decodedKey[decodedKeyLength]; //allocate char array big enough for the base64 decoded key

  base64_decode(decodedKey, key, keyLength); //decode key

  Sha256.initHmac((const uint8_t *)decodedKey, decodedKeyLength);
  Sha256.print(stringToSign);
  char *sign = (char *)Sha256.resultHmac();
  // END: Create signature

  // START: Get base64 of signature
  int encodedSignLen = base64_enc_len(HASH_LENGTH);
  char encodedSign[encodedSignLen];
  base64_encode(encodedSign, sign, HASH_LENGTH);

// SharedAccessSignature
#if SERIAL_DEBUG && MQTT_DEBUG
  Serial.println("sr=" + url + "&sig=" + urlEncode(encodedSign) + "&se=" + String(expire));
#endif
  // sig={signature}&se={expiry}&skn={policyName}&sr={URL-encoded-resourceURI}
  if(is_dps)
  {
    return "SharedAccessSignature sig=" + urlEncode(encodedSign) + "&se=" + String(expire) + "&skn=registration" + "&sr=" + url;
  }
  else
  {
    return "SharedAccessSignature sr=" + url + "&sig="+ urlEncode(encodedSign) + "&se=" + String(expire);
  }
  // END: create SAS
}

void dpsCallback(char *topic, byte *payload, unsigned int length)
{
  uint16_t j = 0;
  uint16_t i = 0;
  uint8_t request_id = 0;
  uint8_t fst_req_id = 1;
  uint8_t snd_req_id = 2;
  char array[1000];
  DynamicJsonDocument json_parser(500);
  Serial.print("topic: ");Serial.println(topic);
  Serial.print("length: ");Serial.println(length);
  for (i = 0; i < length; i++)
  {
    array[i] = (char)payload[i];
  }
  array[length] = '\0';
  Serial.println(array);
  deserializeJson(json_parser, array);
  for (j = 0; j < strlen(topic); j++)
  {
    if (topic[j] == '$')
    {
      if (topic[j + 1] == 'r')
      {
        if (topic[j + 2] == 'i')
        {
          if (topic[j + 3] == 'd')
          {
            if (topic[j + 4] == '=')
            {
              request_id = (uint8_t)topic[j + 5] - 48;
            }  
            if(request_id==snd_req_id)
            {
              if(topic[j-5]=='2'&&topic[j-4]=='0'&&topic[j-3]=='0')
              {
                memcpy(hub, (const char*)json_parser["registrationState"]["assignedHub"], strlen((const char*)json_parser["registrationState"]["assignedHub"]));
                memcpy(device_id, (const char*)json_parser["registrationState"]["deviceId"], strlen((const char*)json_parser["registrationState"]["deviceId"]));
#if SERIAL_DEBUG && MQTT_DEBUG
                Serial.println("--------Assignment received----------");
                Serial.print("Hub assigned: " + String((char*)hub));Serial.print(" ");Serial.println("Device Id: " + String((char*)device_id));
#endif
                dps_assigned=true;
                return;
              }
              else
              {
                fails_dps++;
                return;  
              }
            }
            else
            {
              break;
            }
          }
        }
      }
    }
  }
  if (request_id == fst_req_id)
  {
  #if SERIAL_DEBUG && MQTT_DEBUG
    Serial.println("----------Request correctly sent----------");
  #endif
    status = json_parser["status"];
    if(String(status)!="assigning")
    {// failed
      fails_dps++;
      return;
    }
    operation_id = json_parser["operationId"];
    for (j = strlen(dps_ask_assignment); j > 0; j--)
    {
      if (dps_ask_assignment[j] == '{')
      {
        for (i = 0; i < strlen(operation_id); i++)
        {
          dps_ask_assignment[j+i] = operation_id[i];
        }
        dps_ask_assignment[j+i]='\0';
        break;
      }
    }
#if SERIAL_DEBUG && MQTT_DEBUG
    Serial.println("----------Status assigning----------");
    Serial.print("Op-id: ");
    Serial.println(operation_id);
    Serial.print("--------String to ask assignment---------");
    Serial.println(dps_ask_assignment);
    delay(2000);
#endif
    
    dps_req_ack = true;
  }
  return;
}

bool save2SD()
{
  File file;
// Getting credentials from assignment by DPS
  String mqtt_hub_user_str = String(hub) + "/" + String(device_id) + "/?api-version=2018-06-30";
  mqtt_hub_user_str.toCharArray(mqtt_hub_user, 150);
 // Hub built-in device independent endpoint to subscribe to
  String hub_sub_endpoint_str = "devices/" + String(device_id) + "/messages/devicebound/#";
  hub_sub_endpoint_str.toCharArray(hub_sub_endpoint,150);
  // Hub built-in device independent endpoint to publish to
  String hub_pub_endpoint_str = "devices/" + String(device_id) + "/messages/events/";
  hub_pub_endpoint_str.toCharArray(hub_pub_endpoint,150);
// Get SAS token to  hub
  hub_sas_token_str = createIotHubSASToken(device_key, String(hub), 0);
  hub_sas_token_str.toCharArray(hub_sas_token, hub_sas_token_str.length()+1);
  Serial.println(hub_sas_token);

  file = SD.open(provision, FILE_WRITE);
  if(file)
  {
    if(file.println(mqtt_hub_user_str)>0)
    {
      if(file.println(hub_sub_endpoint_str)>0)
      {
        if(file.println(hub_pub_endpoint_str)>0)
        {
          if(file.println(hub_sas_token_str)>0)
          {
            if(file.println(device_id)>0)
            {
              if(file.println(hub)>0)
              {
                #if SERIAL_DEBUG && SD_DEBUG
                Serial.println("Save Az cred to SD: ");
                Serial.println(mqtt_hub_user_str);
                Serial.println(hub_sub_endpoint_str);
                Serial.println(hub_pub_endpoint_str);
                Serial.println(hub_sas_token_str);
                Serial.println(device_id);
                Serial.println(hub);
                #endif
                return true;
              }
            }
          }
        }
      }
    }
  }
  return false;
}


void setup()
{
  SerialAT.begin(115200);
  Serial.begin(115200);
  SD.begin();
  // Trust all servers
  wifi_client.setInsecure();
  mqtt_client.setBufferSize(1000);
  #if !GPRS_DEBUG
  if (WiFi.status() != WL_CONNECTED)
  {
    WiFi.begin(wifi_ssid, wifi_password);
  }
  while (WiFi.status() != WL_CONNECTED);
  Serial.println("WiFi connected");
  #endif
#if GPRS_DEBUG
  if(!modem.init())
  {
    Serial.println("Failed GPRS");
  }
  vTaskDelay(3000/portTICK_PERIOD_MS);
  if(!modem.gprsConnect(apn, gprsUser, gprsPass))
  {
    Serial.println("Failed GPRS");
  }
#endif
}

void loop()
{
  if(getHubProvisioning())
  {
    Serial.println("Provisioning succeeded");
    if(save2SD())
    {
      #if SERIAL_DEBUG
      Serial.println("Correctly saved to SD");
      #endif
      while(1);
    }
  }
}