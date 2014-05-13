# CXX = gcc
CXX = clang
CFLAGS = -std=c99 -Wextra -Wno-deprecated-declarations -Wno-deprecated -Wall -Wshadow -O -pedantic

SRC_DIR = ./src/
INC_DIR = ./include/
OBJ_DIR = ./

_INCLUDE = trustcloud.h
INCLUDE = $(addprefix $(INC_DIR), $(_INCLUDE))

INC_FLAGS = -I$(INC_DIR)
LDFLAGS = -lm -lcrypto -lssl

_TRUST_SRC = trustcloud.c
TRUST_SRC = $(addprefix $(SRC_DIR), $(_TRUST_SRC))
_TRUST_OBJ = $(addsuffix .o, $(basename $(TRUST_SRC)))
TRUST_OBJ = $(addprefix $(OBJ_DIR), $(_TRUST_OBJ))

CLIENT_PROJ = client
_CLIENT_SRC = $(CLIENT_PROJ).c
CLIENT_SRC = $(addprefix $(SRC_DIR), $(_CLIENT_SRC))
CLIENT_INC = $(INCLUDE)
_CLIENT_OBJ = $(addsuffix .o, $(basename $(CLIENT_SRC)))
CLIENT_OBJ = $(addprefix $(OBJ_DIR), $(_CLIENT_OBJ))

SERV_PROJ = server
_SERV_SRC = $(SERV_PROJ).c
SERV_SRC  = $(addprefix $(SRC_DIR), $(_SERV_SRC))
SERV_INC = $(INCLUDE)
_SERV_OBJ = $(addsuffix .o, $(basename $(SERV_SRC)))
SERV_OBJ = $(addprefix $(OBJ_DIR), $(_SERV_OBJ))

all: $(CLIENT_PROJ) $(SERV_PROJ)

$(CLIENT_PROJ): $(CLIENT_OBJ) $(TRUST_OBJ)
	$(CXX) $(LDFLAGS) -o $(CLIENT_PROJ) $^

$(SERV_PROJ): $(SERV_OBJ) $(TRUST_OBJ)
	$(CXX) $(LDFLAGS) -o $(SERV_PROJ) $^

$(TRUST_OBJ): $(TRUST_SRC) $(INCLUDE)
	$(CXX) -c $(CFLAGS) -o $@ $(INC_FLAGS) $<

$(SERV_OBJ): $(SERV_SRC)
	$(CXX) -c $(CFLAGS) -o $@ $(INC_FLAGS) $<

$(CLIENT_OBJ): $(CLIENT_SRC)
	$(CXX) -c $(CFLAGS) -o $@ $(INC_FLAGS) $<

clean:
	rm $(CLIENT_PROJ) $(SERV_PROJ) $(SERV_OBJ) $(CLIENT_OBJ) $(TRUST_OBJ)
