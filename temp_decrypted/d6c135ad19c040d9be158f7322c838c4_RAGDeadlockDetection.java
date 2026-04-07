import java.util.*;

public class RAGDeadlockDetection {

    static List<List<Integer>> graph;

    static boolean dfs(int node, boolean[] visited, boolean[] recStack) {

        visited[node] = true;
        recStack[node] = true;

        for (int neighbor : graph.get(node)) {

            if (!visited[neighbor]) {
                if (dfs(neighbor, visited, recStack))
                    return true;
            }

            else if (recStack[neighbor]) {
                return true;
            }
        }

        recStack[node] = false;

        return false;
    }

    static boolean detectCycle(int vertices) {

        boolean[] visited = new boolean[vertices];
        boolean[] recStack = new boolean[vertices];

        for (int i = 0; i < vertices; i++) {
            if (!visited[i]) {
                if (dfs(i, visited, recStack))
                    return true;
            }
        }

        return false;
    }

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        System.out.print("Enter number of Processes (n): ");
        int n = sc.nextInt();

        System.out.print("Enter number of Resources (m): ");
        int m = sc.nextInt();

        int vertices = n + m;

        System.out.print("Enter number of edges (E): ");
        int E = sc.nextInt();

        graph = new ArrayList<>();

        for (int i = 0; i < vertices; i++) {
            graph.add(new ArrayList<>());
        }

        System.out.println("Enter edges (u v) one by one:");

        for (int i = 0; i < E; i++) {
            System.out.print("Edge " + (i + 1) + ": ");
            int u = sc.nextInt();
            int v = sc.nextInt();
            graph.get(u).add(v);
        }

        System.out.println("\nGraph constructed with " + vertices + " vertices and " + E + " edges.");
        System.out.println("Cycle Check (Initial):");

        if (detectCycle(vertices)) {
            System.out.println("System State: DEADLOCK DETECTED (Cycle exists in RAG)");
        } else {
            System.out.println("System State: NO DEADLOCK (No cycle found in RAG)");
        }

        sc.close();
    }
}