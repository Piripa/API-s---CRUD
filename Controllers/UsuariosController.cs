using Microsoft.AspNetCore.Mvc;
using Exo.WebApi.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Exo.WebApi.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    [ApiController]
    public class UsuariosController : ControllerBase
    {
        private readonly UsuarioRepository _usuarioRepository;
        public UsuariosController(UsuarioRepository usuarioRepository)
        {
            _usuarioRepository = usuarioRepository;
        }
        [HttpGet]
        public IActionResult Listar()
        {
            return Ok(_usuarioRepository.Listar());
        }
        // [HttpPost]
        // public IActionResult Cadastrar(Usuario usuario)
        // {
        //     _usuarioRepository.Cadastrar(usuario);
        //     return StatusCode(201);
        // }
        public IActionResult Post(Usuario usuario)
        {
            Usuario usuarioBuscado = _usuarioRepository.Login(usuario.Email,usuario.Senha);
            if(usuarioBuscado == null)
            {
                return NotFound("Email ou senha inválidos!");

            }
            //Se o usuário for encontrado,criar token
            //Definir dados que serão fornecidos no token - Payload.
            var claims = new []
            {
                //Armazena na claim o email usuario autenticado
                new Claim(JwtRegisteredClaimNames.Email,usuarioBuscado.Email),
                //Armaazena na claim o id do usuario autenticado
                new Claim(JwtRegisteredClaimNames.Jti,usuarioBuscado.Id.ToString()),
            };
            //Define a chave de acesso ao token
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("exoapi-chave-autenticacao"));
            //Define as credenciais do token
            var creds = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);
            //Gerar o token
            var token = new JwtSecurityToken(
                issuer:"exoapi.webapi", //Emissor do token
                audience:"exoapi.webapi", //Destinatário do token
                claims:claims, //Dados definidor a cima.
                expires: DateTime.Now.AddMinutes(30), // tempo de expiração
                signingCredentials: creds //Creenciais do token.
            );
            //Return ok  com o token.
            return Ok(new{token= new JwtSecurityTokenHandler().WriteToken(token)});
        }
        [HttpGet("{id}")]
        public IActionResult BuscarPorId(int id)
        {
            Usuario usuario = _usuarioRepository.BuscarPorId(id);
            if(usuario == null)
            {
                return NotFound();
            }
            return Ok(usuario);
        }
        [Authorize]   
        [HttpPut("{id}")]
        public IActionResult Atualizar(int id,Usuario usuario)
        {
            _usuarioRepository.Atualizar(id,usuario);
            return StatusCode(204);
        }
        [Authorize]
        [HttpDelete("{id}")]
        public IActionResult Deletar(int id)
        {
            try
            {
                _usuarioRepository.Deletar(id);
                return StatusCode(204);
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }
    }
}