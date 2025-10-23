using System;
using System.IO;
using System.Linq; 
using EmonTool;

namespace EmonTool
{
    public class Program
    {
        private const string UsageMessage = @"
Usage: EmonTool.exe <mode> <paths> [options]

Modes:
    -x <archive.eme> <output_directory>       Extract archive to directory
    -c <input_directory> <archive.eme> [-e]  Create archive (optionally enable encryption)

Options:
    -e     Enable encryption when creating archive

Examples:
    EmonTool.exe -x archive.eme outputDir
    EmonTool.exe -c inputDir archive.eme
    EmonTool.exe -c inputDir archive.eme -e";

        public static int Main(string[] args)
        {
            try
            {
                return ProcessArgs(args);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                return 1;
            }
        }

        private static int ProcessArgs(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine(UsageMessage);
                return 1;
            }

            var mode = args[0].ToLowerInvariant();

            return mode switch
            {
                "-x" => HandleExtract(args),
                "-c" => HandleCreate(args),
                _ => HandleInvalidMode()
            };
        }

        private static int HandleExtract(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Error: Extract mode requires archive path and output directory");
                Console.WriteLine(UsageMessage);
                return 1;
            }

            var archivePath = args[1];
            var outputDir = args[2];

            if (!File.Exists(archivePath))
                throw new FileNotFoundException($"Archive file not found: {archivePath}");

            EnsureDirectoryExists(outputDir);
            return ExtractArchive(archivePath, outputDir);
        }

        private static int HandleCreate(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Error: Create mode requires input directory and archive path");
                Console.WriteLine(UsageMessage);
                return 1;
            }

            var inputDir = args[1];
            var archivePath = args[2];
            bool encrypt = args.Contains("-e", StringComparer.OrdinalIgnoreCase);

            if (!Directory.Exists(inputDir))
                throw new DirectoryNotFoundException($"Input directory not found: {inputDir}");

            EnsureArchivePathValid(archivePath);
            return CreateArchive(archivePath, inputDir, encrypt);
        }

        private static void EnsureDirectoryExists(string directoryPath)
        {
            if (!Directory.Exists(directoryPath))
            {
                try
                {
                    Directory.CreateDirectory(directoryPath);
                    Console.WriteLine($"Created output directory: {directoryPath}");
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException($"Failed to create output directory: {ex.Message}", ex);
                }
            }
        }

        private static void EnsureArchivePathValid(string archivePath)
        {
            var directory = Path.GetDirectoryName(archivePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                throw new DirectoryNotFoundException($"Archive output directory does not exist: {directory}");
            }
        }

        private static int ExtractArchive(string archivePath, string outputDir)
        {
            Console.WriteLine($"Extracting {archivePath} to {outputDir}...");
            var archive = new Eme();
            archive.Unpack(archivePath, outputDir);
            Console.WriteLine("Extraction completed successfully!");
            return 0;
        }

        private static int CreateArchive(string archivePath, string inputDir, bool encrypt)
        {
            Console.WriteLine($"Creating archive {archivePath} from {inputDir}...");
            Console.WriteLine(encrypt ? "Encryption enabled" : "Encryption disabled");

            var packer = new Eme();
            packer.Pack(inputDir, archivePath, encrypt);

            Console.WriteLine("Archive created successfully!");
            return 0;
        }

        private static int HandleInvalidMode()
        {
            Console.WriteLine("Error: Invalid mode specified");
            Console.WriteLine(UsageMessage);
            return 1;
        }
    }
}
