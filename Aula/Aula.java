import java.util.Scanner;

public class Aula {
    public static void main(String[] args){
        System.out.println("Ola mundo");

        Scanner scanner = new Scanner(System.in);

System.out.print("Digite seu nome: ");
String nome = scanner.nextLine();
String Finals = nome.charAt(0) + "" + nome.charAt(2);

System.out.print("digite seu cpf: ");
String cpf = scanner.nextLine();
int A = 0, B;
for (int n = 0; n < 11; n++) {
char num = cpf.charAt(n);
B = Character.getNumericValue(num);
A += B;
}
int D, E, F;

char D1 = cpf.charAt(2);
D = Character.getNumericValue(D1);
char D2 = cpf.charAt(4);
E = Character.getNumericValue(D2);
char D3 = cpf.charAt(6);
F = Character.getNumericValue(D3);

if (E == 0) {
System.out.println("Bem-vindo, " + nome + "! Seu código de acesso é: " + Finals + A + "-" + (D % 1 + F));
} else {
System.out.println("Bem-vindo, " + nome + "! Seu código de acesso é: " + Finals + A + "-" + ((D % E) + F));
}
scanner.close();

}

}


