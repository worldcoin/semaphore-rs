use proc_macro::{Ident, Literal, Span, TokenStream, TokenTree};
use quote::{format_ident, quote, ToTokens};
use semaphore_depth_config::get_supported_depths;
use std::iter;
use syn::parse_macro_input;

// #[derive(Debug)]
// struct ArrayForDepths {
//     replaced_ident: Ident,
//     rest: Expr,
// }
//
// struct IdentReplacer(Ident, Expr);
//
// impl syn::visit_mut::VisitMut for IdentReplacer {
//     fn visit_expr_mut(&mut self, i: &mut Expr) {
//         println!("visiting expr {:?}", i);
//         if let Expr::Path(ident) = i {
//             println!("it's a path alright");
//             if ident.path.is_ident(&self.0) {
//                 println!("hitting this path");
//                 *i = self.1.clone();
//             }
//         }
//         syn::visit_mut::visit_expr_mut(self, i);
//     }
// }
//
// impl Parse for ArrayForDepths {
//     fn parse(input: ParseStream) -> syn::Result<Self> {
//         let replaced_ident = input.parse::<Ident>()?;
//         input.parse::<Token![,]>()?;
//         let rest = input.parse::<Expr>()?;
//         Ok(ArrayForDepths {
//             replaced_ident,
//             rest,
//         })
//     }
// }
//
// impl ArrayForDepths {
//     fn do_the_thing(&mut self) -> TokenStream {
//         IdentReplacer(self.replaced_ident.clone(), parse_quote!(17)).visit_expr_mut(&mut self.rest);
//         let res: TokenStream = self.rest.to_token_stream().into();
//         println!("REPLACED {}", res.to_string());
//         res
//     }
// }

#[proc_macro_attribute]
pub fn test_all_depths(_attr: TokenStream, item: TokenStream) -> TokenStream {
    println!("RUNNING THIS MACRO");
    let fun = parse_macro_input!(item as syn::ItemFn);
    println!("fun: {}", fun.sig.ident.to_string());
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

#[proc_macro]
pub fn array_for_depths(input: TokenStream) -> TokenStream {
    let parts = input.into_iter().collect::<Vec<_>>();
    assert!(parts.len() > 3);
    match &parts[0] {
        TokenTree::Punct(punct) => {
            assert_eq!(punct.as_char(), '|');
            assert_eq!(punct.spacing(), proc_macro::Spacing::Alone);
        }
        _ => panic!("expected a |"),
    }
    match &parts[2] {
        TokenTree::Punct(punct) => {
            assert_eq!(punct.as_char(), '|');
            assert_eq!(punct.spacing(), proc_macro::Spacing::Alone);
        }
        _ => panic!("expected a |"),
    }
    let binder = match &parts[1] {
        TokenTree::Ident(ident) => ident.clone(),
        _ => panic!("expected ident"),
    };
    let rest = parts[3..].to_vec();
    let mut result_items = vec![];
    #[cfg(feature = "depth_16")]
    result_items.push(replace_for_depth(&binder, 16, &rest));
    #[cfg(feature = "depth_20")]
    result_items.push(replace_for_depth(&binder, 20, &rest));
    #[cfg(feature = "depth_30")]
    result_items.push(replace_for_depth(&binder, 30, &rest));
    let comma = TokenTree::Punct(proc_macro::Punct::new(',', proc_macro::Spacing::Alone));
    let replaced = itertools::intersperse(result_items, vec![comma]).flatten();
    let mut result = TokenStream::new();
    result.extend(replaced);
    let grouped = TokenTree::Group(proc_macro::Group::new(
        proc_macro::Delimiter::Bracket,
        result,
    ));
    let grouped = TokenStream::from(grouped);
    grouped
}

fn replace_for_depth(old: &Ident, depth: usize, input: &Vec<TokenTree>) -> Vec<TokenTree> {
    input
        .iter()
        .map(|token| {
            replace_var(
                old,
                &TokenTree::Literal(Literal::usize_unsuffixed(depth)),
                token,
            )
        })
        .collect::<Vec<_>>()
}

fn replace_var(old: &Ident, new: &TokenTree, input: &TokenTree) -> TokenTree {
    match input {
        TokenTree::Ident(ident) => {
            if ident.to_string() == old.to_string() {
                new.clone()
            } else {
                input.clone()
            }
        }
        TokenTree::Group(group) => {
            let mut new_stream = TokenStream::new();
            for token in group.stream() {
                new_stream.extend(iter::once(replace_var(old, new, &token)));
            }
            TokenTree::Group(proc_macro::Group::new(group.delimiter(), new_stream))
        }
        _ => input.clone(),
    }
}
