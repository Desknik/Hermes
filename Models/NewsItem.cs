namespace SimpleNewsSystem.Models;

using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

public class NewsItem
{
    public int id { get; set; }

    [Required(ErrorMessage = "O campo Título é obrigatório.")]
    public required string title { get; set; }

     [Required(ErrorMessage = "O campo Descrição é obrigatório.")]
    public required string description { get; set; }

    [Required(ErrorMessage = "O campo URL da Imagem é obrigatório.")]
    [Url(ErrorMessage = "O campo URL da Imagem deve ser uma URL válida.")]
    public required string image_url { get; set; }
}