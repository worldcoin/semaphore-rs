use proc_macro::TokenStream;
use quote::{format_ident, quote};
use semaphore_depth_config::get_supported_depths;
use syn::parse::{Parse, ParseStream};
use syn::visit_mut::VisitMut;
use syn::{parse_macro_input, parse_quote, Ident, Token};

#[proc_macro_attribute]
pub fn test_all_depths(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let fun = parse_macro_input!(item as syn::ItemFn);
    let fun_name = &fun.sig.ident;

    let original_fun = quote! { #fun };
    let mut result = TokenStream::from(original_fun);

    for depth in get_supported_depths() {
        let fun_name_versioned = format_ident!("{}_depth_{}", fun_name, depth);
        let tokens = quote! {
            #[test]
            fn #fun_name_versioned() {
                #fun_name(#depth);
            }
        };
        result.extend(TokenStream::from(tokens));
    }
    result
}

#[derive(Debug)]
struct ArrayForDepthsInput {
    replaced_ident: Ident,
    expr: syn::Expr,
}

#[derive(Debug)]
struct MacroArgs {
    args: Vec<syn::Expr>,
}

impl Parse for MacroArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut args = Vec::new();
        while !input.is_empty() {
            args.push(input.parse::<syn::Expr>()?);
            if input.is_empty() {
                break;
            }
            input.parse::<Token![,]>()?;
        }
        Ok(MacroArgs { args })
    }
}

impl MacroArgs {
    fn tokens(&self) -> proc_macro2::TokenStream {
        let args = &self.args;
        (quote! { #(#args),* }).into()
    }
}

struct IdentReplacer(Ident, syn::Expr);

impl VisitMut for IdentReplacer {
    fn visit_expr_mut(&mut self, expr: &mut syn::Expr) {
        match expr {
            syn::Expr::Path(ident) => {
                if ident.path.is_ident(&self.0) {
                    *expr = self.1.clone();
                }
            }
            syn::Expr::Macro(mcr) => {
                let Ok(mut args) =  mcr.mac.parse_body::<MacroArgs>() else {
                     return;
                };
                for arg in &mut args.args {
                    self.visit_expr_mut(arg);
                }
                mcr.mac.tokens = args.tokens();
            }
            _ => syn::visit_mut::visit_expr_mut(self, expr),
        }
    }
}

impl Parse for ArrayForDepthsInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        input.parse::<Token![|]>()?;
        let replaced_ident = input.parse::<Ident>()?;
        input.parse::<Token![|]>()?;
        let expr = input.parse::<syn::Expr>()?;
        Ok(ArrayForDepthsInput {
            replaced_ident,
            expr,
        })
    }
}

#[proc_macro]
pub fn array_for_depths(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ArrayForDepthsInput);
    let items = get_supported_depths()
        .iter()
        .map(|depth| {
            let mut replacer = IdentReplacer(input.replaced_ident.clone(), parse_quote!(#depth));
            let mut expr = input.expr.clone();
            replacer.visit_expr_mut(&mut expr);
            expr
        })
        .collect::<Vec<_>>();
    let array = quote! { [#(#items),*] };
    array.into()
}
