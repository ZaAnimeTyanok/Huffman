#define _CRT_SECURE_NO_WARNINGS
#include "stdio.h"
#include "string.h"
#include "stdlib.h"

#define or ||
#define and &&
#define BUFFER_SIZE 512

typedef struct table_item {
	unsigned char sym;
	unsigned int count;
}table_item;

typedef struct t_node {
	unsigned char sym;
	unsigned int count;
	
	struct t_node* left;
	struct t_node* right;
}t_node;


typedef struct priority_queue_item {
	t_node* node;
	unsigned int priority;
	struct priority_queue_item* next;

}priority_queue_item;

typedef struct huff_table {
	unsigned char code[256];
	int len;
}huff_table;

typedef struct priority_queue {
	priority_queue_item* head;
}priority_queue;

typedef struct bit_contex {
	unsigned char buffer;
	int pos;
}bit_context;

table_item* table_make() {
	table_item* table = (table_item*)calloc(256, sizeof(table_item));
	return table;
}

unsigned int table_fill(FILE* input, table_item* table) {
	unsigned char* buffer = (unsigned char*)malloc(BUFFER_SIZE * sizeof(unsigned char));
	unsigned int total = 0;
	
	while (1) {
		size_t amount_of_symbols = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, input);
		total += (unsigned int)amount_of_symbols;
		
		for (int i = 0; i < (int)amount_of_symbols; i++) {
			table[(int)buffer[i]].sym = buffer[i];
			table[(int)buffer[i]].count++;
		}
		
		if (amount_of_symbols < BUFFER_SIZE) {
			break;
		}
	}
	
	free(buffer);
	return total;
}

int compare(const void* a, const void* b) {
	const table_item* item1 = (const table_item*)a;
	const table_item* item2 = (const table_item*)b;
	
	if (item1->count != item2->count) {
		return item1->count - item2->count;
	}
	
	return (int)(item1->sym) - (int)(item2->sym);
}

priority_queue* pr_queue_make() {
	priority_queue* queue = (priority_queue*)calloc(1, sizeof(priority_queue));
	return queue;
}

void append(priority_queue* queue, t_node* node, unsigned int priority) {
	priority_queue_item* item = (priority_queue_item*)malloc(sizeof(priority_queue_item));
	item->priority = priority;
	item->node = node;
	
	if (queue->head == NULL) {
		item->next = NULL;
		queue->head = item;
	}
	
	else {
		priority_queue_item* current = queue->head;
		priority_queue_item* last = NULL;
		
		while (1) {
			if (current->priority > priority) {
				if (last == NULL) {
					item->next = current;
					queue->head = item;
				}
				
				else {
					item->next = current;
					last->next = item;
				}
				
				break;
			}
			
			else {
				last = current;
				current = last->next;
				
				if (current == NULL) {
					item->next = NULL;
					last->next = item;
					
					break;
				}
			}
		}

	}
}

t_node* pop(priority_queue* queue) {
	priority_queue_item* item = queue->head;
	queue->head = item->next;
	
	t_node* node = item->node;
	free(item);
	
	return node;
}

void pr_queue_destroy(priority_queue* queue) {
	free(queue);
}

int queue_length(priority_queue* queue) {
	priority_queue_item* item = queue->head;
	
	if (item == NULL) {
		return 0;
	}
	
	int len = 1;
	
	while (item->next != NULL) {
		len++;
		item = item->next;
	}
	
	return len;
}

t_node* node_make(table_item item) {
	t_node* node = (t_node*)calloc(1, sizeof(t_node));
	node->count = item.count;
	node->sym = item.sym;
	
	return node;
}

void queue_fill(priority_queue* queue, table_item* hash_table) {
	for (int i = 0; i < 256; i++) {
		if (hash_table[i].count != 0) {
			t_node* node = node_make(hash_table[i]);
			append(queue, node, hash_table[i].count);
		}
	}
}

void tree_cleaning(t_node* root) {
	if (root == NULL) { 
		return; 
	}
	
	tree_cleaning(root->left);
	tree_cleaning(root->right);
	free(root);
}

void clean_all(FILE* input, FILE* output, priority_queue* queue, table_item* table, t_node* root, huff_table* h_table) {
	fclose(input);
	fclose(output);
	free(table);
	free(h_table);
	
	pr_queue_destroy(queue);
	tree_cleaning(root);
}

t_node* unite(t_node* node1, t_node* node2) {
	t_node* new_node = (t_node*)calloc(1, sizeof(t_node));
	new_node->count = node1->count + node2->count;
	new_node->left = node1;
	new_node->right = node2;
	
	return new_node;
}

t_node* huff_tree_make(priority_queue* queue) {
	int len = queue_length(queue);
	
	while (len > 1) {
		t_node* node1 = pop(queue);
		t_node* node2 = pop(queue);
		t_node* new_node = unite(node1, node2);
		append(queue, new_node, new_node->count);
		len--;
	}
	
	return pop(queue);
}

huff_table* huff_table_create() {
	huff_table* table = (huff_table*)calloc(256, sizeof(huff_table));
	return table;
}

void huff_table_fill(t_node* root, unsigned char code[256], int* idx, huff_table* table) {
	if (root == NULL) { 
		return; 
	}
	
	if (root->left != NULL or root->right != NULL) {
		code[*idx] = '0';
		*idx += 1;
		huff_table_fill(root->left, code, idx, table);
	}
	
	if (root->left != NULL or root->right != NULL) { *idx -= 1; }
	
	if (root->left == NULL and root->right == NULL) {
		table[(int)(root->sym)].len = *idx;
		memcpy(table[(int)(root->sym)].code, code, *idx);

	}
	
	if (root->left != NULL or root->right != NULL) {
		code[*idx] = '1';
		*idx += 1;
		huff_table_fill(root->right, code, idx, table);
		*idx -= 1;
	}
}

void bit_write(FILE* output, bit_context* context, unsigned char bit) {
	if (context->pos == 8) {
		fwrite(&(context->buffer), sizeof(char), 1, output);
		context->pos = 0;
		context->buffer = 0;
	}
	
	if (bit) {
		context->buffer = context->buffer | (bit << (7 - context->pos));
	}
	
	context->pos++;
}

void bit_context_clean(FILE* output, bit_context* context) {
	fwrite(&(context->buffer), sizeof(char), 1, output);
	context->pos = 0;
	context->buffer = 0;
}

void byte_write(FILE* output, bit_context* context, unsigned char byte) {
	for (int i = 0; i <= 7; i++) {
		bit_write(output, context, (byte >> (7 - i)) & 1);
	}
}

void huff_code_write(huff_table item, bit_context* context, FILE* output) {
	for (int i = 0; i < item.len; i++) {
		if (item.code[i] == '1') {
			bit_write(output, context, 1);
		}
		
		else {
			bit_write(output, context, 0);
		}
	}
}

void encode_huff_tree(t_node* root, bit_context* context, FILE* output) {
	if (root == NULL) { 
		return; 
	}
	
	if (root->left == NULL and root->right == NULL) {
		bit_write(output, context, 1);
		byte_write(output, context, root->sym);
	}
	
	else {
		bit_write(output, context, 0);
		encode_huff_tree(root->left, context, output);
		encode_huff_tree(root->right, context, output);
	}

}

void encode_count_symbols(FILE* output, t_node* root, unsigned int amount_of_symbols, bit_context* context) {
	for (int i = 0; i <= 31; i++) {
		bit_write(output, context, (unsigned char)((amount_of_symbols >> (31 - i)) & 1));
	}
	
	encode_huff_tree(root, context, output);
}

void encode(FILE* input, FILE* output, bit_context* context, huff_table* table) {
	fseek(input, 1, SEEK_SET);
	unsigned char* buffer = (unsigned char*)malloc(BUFFER_SIZE * sizeof(unsigned char));

	while (1) {
		size_t amount_of_symbols = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, input);
		
		for (int i = 0; i < (int)amount_of_symbols; i++) {
			huff_code_write(table[(int)buffer[i]], context, output);
		}
		
		if (amount_of_symbols < BUFFER_SIZE) {
			break;
		}
	
	}
	
	bit_context_clean(output, context);
	free(buffer);
}

unsigned char bit_read(bit_context* ctx, FILE* input) {
	if (!(ctx->pos)) {
		size_t count = fread(&(ctx->buffer), sizeof(char), 1, input);
		
		if (!(count)) {
			return 2;
		}
	}
	
	unsigned char bit = (ctx->buffer >> (7 - ctx->pos)) & 1;
	ctx->pos++;
	
	if (ctx->pos == 8) {
		ctx->pos = 0;
	}

	return bit;
}

unsigned char byte_read(bit_context* ctx, FILE* input) {
	unsigned char byte = 0;
	
	for (int i = 0; i < 8; i++) {
		byte = byte | (bit_read(ctx, input) << (7 - i));
	}
	
	return byte;
}

unsigned int read_count_symbols(FILE* input, bit_context* ctx) {
	unsigned int alphabet = 0;
	
	for (int i = 0; i < 32; i++) {
		unsigned char bit = bit_read(ctx, input);
		alphabet = alphabet | (((unsigned int)bit) << (31 - i));
	}
	
	return alphabet;
}

t_node* tree_read(bit_context* ctx, FILE* input) {
	int bit = (int)bit_read(ctx, input);
	t_node* node = (t_node*)calloc(1, sizeof(t_node));
	
	if (!(bit)) {
		node->left = tree_read(ctx, input);
		node->right = tree_read(ctx, input);
	}
	
	else {
		node->sym = byte_read(ctx, input);
	}
	
	return node;
}

unsigned char get_symbol(FILE* input, bit_context* ctx, t_node* root) {
	if (root->left == NULL and root->right == NULL) {
		return root->sym;
	}
	
	int bit = (int)bit_read(ctx, input);
	unsigned char sym;

	if (!(bit)) {
		sym = get_symbol(input, ctx, root->left);
	}
	
	else {
		sym = get_symbol(input, ctx, root->right);
	}
	
	return sym;
}


void decode(FILE* input, FILE* output, bit_context* ctx, t_node* root, unsigned int amount_of_symbols) {
	unsigned char sym;
	
	for (int i = 0; i < (int)amount_of_symbols; i++) {
		sym = get_symbol(input, ctx, root);
		fwrite(&sym, sizeof(char), 1, output);
	}
}

int main() {
	FILE* input = fopen("in.txt", "rb");
	FILE* output = fopen("out.txt", "wb");

	char what_to_do;
	
	if (fscanf(input, "%c", &what_to_do) != 1) {
		fclose(input);
		fclose(output);
		
		return 0;
	}

	if (what_to_do == 'c') {
		table_item* hash_table = table_make();
		unsigned int amount_of_symbols = table_fill(input, hash_table);

		if (!(amount_of_symbols)) {
			clean_all(input, output, NULL, hash_table, NULL, NULL);
			return 0;
		}

		qsort(hash_table, 256, sizeof(table_item), compare);
	
		priority_queue* queue = pr_queue_make();
		queue_fill(queue, hash_table);
		
		t_node* root = huff_tree_make(queue);
		huff_table* huff_table = huff_table_create();
		
		int idx = 0;
		unsigned char code[256] = { 0 };
		
		huff_table_fill(root, code, &idx, huff_table);
		
		bit_context context = { 0 };
		
		encode_count_symbols(output, root, amount_of_symbols, &context);
		encode(input, output, &context, huff_table);
		
		clean_all(input, output, queue, hash_table, root, huff_table);
	}
	
	else if (what_to_do == 'd') {
		bit_context context = { 0 };
		unsigned int total = read_count_symbols(input, &context);
		
		if (!(total)) {
			clean_all(input, output, NULL, NULL, NULL, NULL);
			return 0;
		}
		
		t_node* huff_tree = tree_read(&context, input);
		
		decode(input, output, &context, huff_tree, total);
		
		clean_all(input, output, NULL, NULL, huff_tree, NULL);
	}
	
	return 0;

}
