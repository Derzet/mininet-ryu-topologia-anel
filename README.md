# MininetRyu

Este projeto realizado para a disciplina de Redes de Computadores consiste de criar uma Software-Defined Networking utilizando Ryu
como controlador da rede e Mininet para criação da topologia, utilizamos o protocolo OpenFlow 1.3 para configurar os Switches.


O que é Mininet?

             Mininet é um emulador virtual de rede, permitindo a criação de diferentes topologias customizadas de redes, 
             a plataforma permite configurar e escolher a quantidade de  switches, roteadores, hosts, controladores e links que 
             serão utilizados para a construção da rede. Dessa forma permitindo a simulação de uma rede de ambiente real criando
             uma Software-Defined Networking. Mininet possui como uma das principais vantagem funcionar em um único Kernel do Linux 
             reduzindo custo de projetos e acelerando testes.
             Informações MININET: https://github.com/mininet/mininet
             

O que é Ryu?

              Ryu é um controle de Software-defined networking (SDN) podendo ajudar a gerenciar o tráfego da rede, aumentar a largura 
              da banda, alocar recursos, criar fluxos e entre outras demais funções de configurações. Utilizando o Ryu como controle torna 
              mais fácil o gerenciamento e adaptar tráficos, dessa forma o conceito de SDN torna-se mais consolidado nos tempos reais, aos 
              quais poderão ser gerenciado por um único controlador.
              Informações RYU: https://github.com/osrg/ryu
              
 Estrutura Rede Mininet  
  A topologia consiste de 6 hosts(Sendo 3 Clientes e 3 Servidores), 3 switches e 1 controlador principal 
  com limitação de banda em 30KB/s entre os links.
  

             
 SW = Switch
 S = Servidor
 C = Cliente
 CO = Controlador

Políticas Estáticas

   Para a criação das políticas estáticas alguns Controladores e APIs do RYU foram analisadas.
Observando o controlador Simple_Switch_13.py foram necessárias algumas modificações. Devido a este controlador não suporta o loop dos
pacotes Address Resolution Protocol (ARP) foram feitas mudanças para o funcionamento da mesma criando novas regras e inserção de código
para fazer a correção, a princípio cogitou-se o uso do Spanning Protocol Tree sendo um protocolo de rede que permite resolver problemas
de loops com lógica de portas. Devido algumas incompatibilidade de biblioteca optamos por utilizar uma solução mais simples, no qual 
através da memória verificamos se o ARP está em loop, caso estiver saia do loop descartando o pacote. Além disso, utilizamos a API de 
QOS fazendo uso da ryu.app.rest_qos e ryu.app.rest_conf_switch para configuração das Queues. Dessa forma a limitação da banda entre os
links está em 30KB/s, equivalente a 240 Kb/s para efeito de comparação, realizando a restrição de banda. O novo controlador é
denominado de mySwitch.py

Políticas Dinâmicas

  Para definimos utilizamos ryu.app.rest_conf_switch, ryu.app.rest_qos e ryu.app.mySwitch.
Primeiramente realizamos a configuração dos switches conectando as QOS adicionando a table_id=1. Através de alguns 
requests HTTP configuramos o restante das queues e regras restantes, definimos duas filas a fluxo normal configurada 
como sendo a queue Padrão [min:0 Kbp/s,max:240 Kbp/s] e a BackUP [min:160Kbps/s] equivalente a alocar os 20 KB/s .
Através de uma verificação no tempo  e entrada de valores utilizando o método reservaBanda() e alocaBanda() verificamos 
se devemos usar a queue padrão ou backup entre comunicação TCP entre os Servers. Quando estiver em horário de backup configuramos
o fluxo para utilizar a queue de Backup, caso contrário utilizamos a queue padrão a regra é atualizada a cada 60 segundos





