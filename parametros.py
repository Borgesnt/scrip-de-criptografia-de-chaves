from diffiehellman import DiffieHellman

# Gera automaticamente dois pares de chaves
dh1 = DiffieHellman(group=14, key_bits=540)
dh2 = DiffieHellman(group=14, key_bits=540)

# Obtém as chaves públicas de ambos os lados
dh1_public = dh1.get_public_key()
dh2_public = dh2.get_public_key()

# Gera a chave compartilhada com base na chave pública do outro lado
dh1_shared = dh1.generate_shared_key(dh2_public)
dh2_shared = dh2.generate_shared_key(dh1_public)

# As chaves compartilhadas devem ser iguais
assert dh1_shared == dh2_shared

print("Chave compartilhada gerada com sucesso!")
# Você pode usar dh1_shared (ou dh2_shared) como sua chave simétrica agora
# print(f"Chave compartilhada: {dh1_shared.hex()}")