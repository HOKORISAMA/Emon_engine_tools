using System;
using System.IO;
using EmonTool;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length != 3)
        {
            Console.WriteLine("Usage: EmonTool.exe <archive.eme> <output_directory><-c|-x>");
            return 1;
        }

        string archivePath = args[0];
        string outputDir = args[1];
        string mode = args[2];


        switch (mode)
        {
            case "-x":
                if (!File.Exists(archivePath))
                {
                    Console.Error.WriteLine($"Archive file not found: {archivePath}");
                    return 1;
                }

                var archive = new EME();

                archive.Unpack(archivePath, outputDir);
                Console.WriteLine("Extraction complete!");
                return 0;

            case "-c":
                if (!Directory.Exists(outputDir))
                {
                    Console.WriteLine($"Error: Input directory does not exist: {outputDir}");
                    return 1;
                }

                var packer = new EME();
                packer.Pack(outputDir, archivePath);
                Console.WriteLine("Packing complete!");
                return 0;

            default:
                Console.WriteLine("Invalid mode. Use '-x' or '-c'.");
                return 1;
        }
    }
}
